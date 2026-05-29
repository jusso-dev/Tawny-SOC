import type { SigmaRule, SocEvent } from "../types";
import { ruleMatchesPayload } from "../sigma";
import { filterWithYaaql } from "../yaaql";
import {
  type DetectionLifecycleStatus,
  lifecycleStatusForSigma,
  normalizeDetectionStatus,
  shouldEvaluateDetectionStatus,
} from "./lifecycle";

export type DetectionTestMatcher<T extends SocEvent = SocEvent> = (record: T) => boolean;

export type TestableDetection<T extends SocEvent = SocEvent> = {
  id: string;
  title?: string;
  status?: DetectionLifecycleStatus | SigmaRule["status"];
  query?: string;
  matcher?: DetectionTestMatcher<T>;
  sigmaRule?: SigmaRule;
};

export type DetectionTestCase<T extends SocEvent = SocEvent> = {
  name?: string;
  records: T[];
  expectedMatchIds: string[];
  expectedNonMatchIds?: string[];
  tenantId?: string;
  allowAdditionalMatches?: boolean;
};

export type DetectionTestResult<T extends SocEvent = SocEvent> = {
  detectionId: string;
  name?: string;
  status: DetectionLifecycleStatus;
  passed: boolean;
  skipped: boolean;
  expectedMatchIds: string[];
  actualMatchIds: string[];
  missingMatchIds: string[];
  unexpectedMatchIds: string[];
  matchedRecords: T[];
  errors: string[];
};

export type DetectionTestSuiteResult<T extends SocEvent = SocEvent> = {
  detectionId: string;
  passed: boolean;
  results: Array<DetectionTestResult<T>>;
};

export function testableSigmaRule(rule: SigmaRule, options: { disabled?: boolean } = {}): TestableDetection {
  return {
    id: rule.id,
    title: rule.title,
    status: lifecycleStatusForSigma(rule, options),
    sigmaRule: rule,
  };
}

export function runDetectionTest<T extends SocEvent>(
  detection: TestableDetection<T>,
  testCase: DetectionTestCase<T>,
): DetectionTestResult<T> {
  const status = normalizeDetectionStatus(detection.status, "test");
  const expectedMatchIds = unique(testCase.expectedMatchIds);
  const scopedRecords = testCase.tenantId === undefined
    ? testCase.records
    : testCase.records.filter((record) => record.tenantId === testCase.tenantId);

  if (!shouldEvaluateDetectionStatus(status, "test")) {
    return buildResult({
      detection,
      testCase,
      status,
      expectedMatchIds,
      matchedRecords: [],
      skipped: true,
      errors: [],
    });
  }

  const evaluation = evaluateDetection(detection, scopedRecords);

  return buildResult({
    detection,
    testCase,
    status,
    expectedMatchIds,
    matchedRecords: evaluation.records,
    skipped: false,
    errors: evaluation.errors,
  });
}

export function runDetectionTests<T extends SocEvent>(
  detection: TestableDetection<T>,
  testCases: Array<DetectionTestCase<T>>,
): DetectionTestSuiteResult<T> {
  const results = testCases.map((testCase) => runDetectionTest(detection, testCase));
  return {
    detectionId: detection.id,
    passed: results.every((result) => result.passed),
    results,
  };
}

function evaluateDetection<T extends SocEvent>(detection: TestableDetection<T>, records: T[]) {
  if (detection.matcher) {
    return {
      records: records.filter((record) => detection.matcher?.(record)),
      errors: [],
    };
  }

  if (detection.query?.trim()) {
    const result = filterWithYaaql(records, detection.query);
    return {
      records: result.records,
      errors: result.error ? [result.error] : [],
    };
  }

  if (detection.sigmaRule) {
    return {
      records: records.filter((record) => ruleMatchesPayload(
        detection.sigmaRule as SigmaRule,
        record.payload,
        record.eventType,
        record.ruleId,
      )),
      errors: [],
    };
  }

  return {
    records: [],
    errors: ["Detection tests require a matcher, query, or sigmaRule."],
  };
}

function buildResult<T extends SocEvent>(input: {
  detection: TestableDetection<T>;
  testCase: DetectionTestCase<T>;
  status: DetectionLifecycleStatus;
  expectedMatchIds: string[];
  matchedRecords: T[];
  skipped: boolean;
  errors: string[];
}): DetectionTestResult<T> {
  const actualMatchIds = unique(input.matchedRecords.map((record) => record.id));
  const expected = new Set(input.expectedMatchIds);
  const actual = new Set(actualMatchIds);
  const expectedNonMatches = new Set(input.testCase.expectedNonMatchIds ?? []);

  const missingMatchIds = input.expectedMatchIds.filter((id) => !actual.has(id));
  const unexpectedByExpectation = input.testCase.allowAdditionalMatches
    ? []
    : actualMatchIds.filter((id) => !expected.has(id));
  const unexpectedNonMatches = actualMatchIds.filter((id) => expectedNonMatches.has(id));
  const unexpectedMatchIds = unique([...unexpectedByExpectation, ...unexpectedNonMatches]);

  return {
    detectionId: input.detection.id,
    name: input.testCase.name,
    status: input.status,
    passed: input.errors.length === 0
      && missingMatchIds.length === 0
      && unexpectedMatchIds.length === 0
      && (!input.skipped || input.expectedMatchIds.length === 0),
    skipped: input.skipped,
    expectedMatchIds: input.expectedMatchIds,
    actualMatchIds,
    missingMatchIds,
    unexpectedMatchIds,
    matchedRecords: input.matchedRecords,
    errors: input.errors,
  };
}

function unique(values: string[]) {
  return [...new Set(values)];
}
