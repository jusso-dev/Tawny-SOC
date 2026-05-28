import type { SocEvent } from "@/lib/types";

type TokenKind = "word" | "string" | "operator" | "lparen" | "rparen" | "comma" | "eof";

type Token = {
  kind: TokenKind;
  value: string;
  position: number;
};

type Scalar = string | number | boolean;

type FieldOperator = ":" | "=" | "!=" | ">" | ">=" | "<" | "<=";

type YaaqlNode =
  | { type: "and"; left: YaaqlNode; right: YaaqlNode }
  | { type: "or"; left: YaaqlNode; right: YaaqlNode }
  | { type: "not"; node: YaaqlNode }
  | { type: "field"; field: string; operator: FieldOperator; value: string }
  | { type: "in"; field: string; values: string[] }
  | { type: "exists"; field: string }
  | { type: "text"; value: string };

export type YaaqlSearchResult<T extends SocEvent> = {
  query: string;
  records: T[];
  error?: string;
};

const FIELD_ALIASES: Record<string, string[]> = {
  agent: ["agentId"],
  command: ["commandLine", "command_line"],
  commandline: ["commandLine", "command_line"],
  cmd: ["commandLine", "command_line"],
  domain: ["domain", "query_name", "queryName", "dns_query", "url_domain"],
  event: ["eventType"],
  externalip: ["externalIps", "destination_ip", "remote_ip"],
  hash: ["hash", "sha256", "sha1", "md5", "imphash"],
  host: ["hostname"],
  ip: ["externalIps", "externalIp", "destination_ip", "source_ip", "remote_ip", "ip"],
  mitre: ["mitreTechniques"],
  playbook: ["recommendedPlaybook"],
  rule: ["ruleId", "matchedRules"],
  rules: ["matchedRules"],
  technique: ["mitreTechniques"],
  tenant: ["tenantId"],
  time: ["timestamp"],
  type: ["eventType"],
};

function isOperatorChar(value: string) {
  return value === ":" || value === "=" || value === "!" || value === ">" || value === "<";
}

function isWordBoundary(value: string) {
  return /\s/.test(value) || value === "(" || value === ")" || value === "," || value === "\"" || value === "'" || isOperatorChar(value);
}

function tokenize(input: string) {
  const tokens: Token[] = [];
  let index = 0;

  while (index < input.length) {
    const char = input[index];
    if (/\s/.test(char)) {
      index += 1;
      continue;
    }

    if (char === "(" || char === ")" || char === ",") {
      tokens.push({
        kind: char === "(" ? "lparen" : char === ")" ? "rparen" : "comma",
        value: char,
        position: index,
      });
      index += 1;
      continue;
    }

    if (char === "\"" || char === "'") {
      const quote = char;
      const position = index;
      let value = "";
      index += 1;

      while (index < input.length) {
        const next = input[index];
        if (next === "\\") {
          value += input[index + 1] ?? "";
          index += 2;
          continue;
        }
        if (next === quote) break;
        value += next;
        index += 1;
      }

      if (input[index] !== quote) {
        throw new Error(`Unclosed quote at character ${position + 1}.`);
      }

      tokens.push({ kind: "string", value, position });
      index += 1;
      continue;
    }

    if (isOperatorChar(char)) {
      const position = index;
      const pair = input.slice(index, index + 2);
      if (pair === "!=" || pair === ">=" || pair === "<=") {
        tokens.push({ kind: "operator", value: pair, position });
        index += 2;
        continue;
      }
      if (char === "!") {
        throw new Error(`Unsupported operator at character ${position + 1}; use !=.`);
      }
      tokens.push({ kind: "operator", value: char, position });
      index += 1;
      continue;
    }

    const position = index;
    let value = "";
    while (index < input.length) {
      const next = input[index];
      if (next === ":" && /\d/.test(input[index - 1] ?? "") && /\d/.test(input[index + 1] ?? "")) {
        value += next;
        index += 1;
        continue;
      }
      if (isWordBoundary(next)) break;
      value += next;
      index += 1;
    }

    tokens.push({ kind: "word", value, position });
  }

  tokens.push({ kind: "eof", value: "", position: input.length });
  return tokens;
}

class YaaqlParser {
  private index = 0;

  constructor(private readonly tokens: Token[]) {}

  parse() {
    const expression = this.parseOr();
    if (this.peek().kind !== "eof") {
      throw new Error(`Unexpected token "${this.peek().value}" at character ${this.peek().position + 1}.`);
    }
    return expression;
  }

  private parseOr(): YaaqlNode {
    let node = this.parseAnd();
    while (this.matchWord("or")) {
      node = { type: "or", left: node, right: this.parseAnd() };
    }
    return node;
  }

  private parseAnd(): YaaqlNode {
    let node = this.parseUnary();

    while (true) {
      if (this.matchWord("and")) {
        node = { type: "and", left: node, right: this.parseUnary() };
        continue;
      }

      const next = this.peek();
      if (next.kind === "eof" || next.kind === "rparen" || this.isWord(next, "or")) break;
      if (!this.canStartExpression(next)) break;

      node = { type: "and", left: node, right: this.parseUnary() };
    }

    return node;
  }

  private parseUnary(): YaaqlNode {
    if (this.matchWord("not")) return { type: "not", node: this.parseUnary() };
    return this.parsePrimary();
  }

  private parsePrimary(): YaaqlNode {
    if (this.matchKind("lparen")) {
      const expression = this.parseOr();
      this.expectKind("rparen", "Expected closing parenthesis.");
      return expression;
    }

    return this.parsePredicate();
  }

  private parsePredicate(): YaaqlNode {
    const first = this.expectValue("Expected a field name or search term.");
    const firstLower = first.value.toLowerCase();

    if (first.kind === "word" && firstLower === "has") {
      this.matchOperator(":") || this.matchOperator("=");
      return { type: "exists", field: this.expectValue("Expected a field name after has.").value };
    }

    if (first.kind === "word" && this.matchWord("in")) {
      return { type: "in", field: first.value, values: this.parseValueList() };
    }

    if (first.kind === "word" && this.peek().kind === "operator") {
      const operator = this.advance().value as FieldOperator;
      if (!isFieldOperator(operator)) {
        throw new Error(`Unsupported operator "${operator}" at character ${this.previous().position + 1}.`);
      }
      if (operator === ":" && firstLower === "has") {
        return { type: "exists", field: this.expectValue("Expected a field name after has:.").value };
      }
      return { type: "field", field: first.value, operator, value: this.expectValue("Expected a value after operator.").value };
    }

    return { type: "text", value: first.value };
  }

  private parseValueList() {
    const values: string[] = [];

    if (!this.matchKind("lparen")) {
      return [this.expectValue("Expected a value after in.").value];
    }

    while (this.peek().kind !== "rparen") {
      values.push(this.expectValue("Expected a value inside in (...).").value);
      if (!this.matchKind("comma")) break;
    }

    this.expectKind("rparen", "Expected closing parenthesis after in list.");
    if (values.length === 0) throw new Error("Expected at least one value inside in (...).");
    return values;
  }

  private canStartExpression(token: Token) {
    return token.kind === "word" || token.kind === "string" || token.kind === "lparen";
  }

  private expectValue(message: string) {
    const token = this.advance();
    if (token.kind !== "word" && token.kind !== "string") {
      throw new Error(`${message} Got "${token.value || token.kind}" at character ${token.position + 1}.`);
    }
    return token;
  }

  private expectKind(kind: TokenKind, message: string) {
    if (!this.matchKind(kind)) {
      throw new Error(`${message} Got "${this.peek().value || this.peek().kind}" at character ${this.peek().position + 1}.`);
    }
  }

  private matchKind(kind: TokenKind) {
    if (this.peek().kind !== kind) return false;
    this.index += 1;
    return true;
  }

  private matchOperator(value: string) {
    if (this.peek().kind !== "operator" || this.peek().value !== value) return false;
    this.index += 1;
    return true;
  }

  private matchWord(value: string) {
    if (!this.isWord(this.peek(), value)) return false;
    this.index += 1;
    return true;
  }

  private isWord(token: Token, value: string) {
    return token.kind === "word" && token.value.toLowerCase() === value;
  }

  private previous() {
    return this.tokens[this.index - 1];
  }

  private peek() {
    return this.tokens[this.index];
  }

  private advance() {
    const token = this.peek();
    this.index += 1;
    return token;
  }
}

function isFieldOperator(value: string): value is FieldOperator {
  return value === ":" || value === "=" || value === "!=" || value === ">" || value === ">=" || value === "<" || value === "<=";
}

export function parseYaaql(query: string) {
  const normalizedQuery = query.trim();
  if (!normalizedQuery) return undefined;
  return new YaaqlParser(tokenize(normalizedQuery)).parse();
}

export function filterWithYaaql<T extends SocEvent>(records: T[], query: string): YaaqlSearchResult<T> {
  const normalizedQuery = query.trim();
  if (!normalizedQuery) return { query: normalizedQuery, records };

  try {
    const ast = parseYaaql(normalizedQuery);
    if (!ast) return { query: normalizedQuery, records };
    return {
      query: normalizedQuery,
      records: records.filter((record) => evaluateNode(ast, record)),
    };
  } catch (error) {
    return {
      query: normalizedQuery,
      records: [],
      error: error instanceof Error ? error.message : "Invalid YAAQL query.",
    };
  }
}

export function quoteYaaqlValue(value: string) {
  return `"${value.replace(/["\\]/g, "\\$&")}"`;
}

function evaluateNode(node: YaaqlNode, record: SocEvent): boolean {
  switch (node.type) {
    case "and":
      return evaluateNode(node.left, record) && evaluateNode(node.right, record);
    case "or":
      return evaluateNode(node.left, record) || evaluateNode(node.right, record);
    case "not":
      return !evaluateNode(node.node, record);
    case "field":
      return evaluateField(record, node.field, node.operator, node.value);
    case "in":
      return evaluateIn(record, node.field, node.values);
    case "exists":
      return getFieldValues(record, node.field).some(hasValue);
    case "text":
      return matchPattern(recordSearchText(record), node.value, "contains");
  }
}

function evaluateField(record: SocEvent, field: string, operator: FieldOperator, expected: string) {
  const values = getFieldValues(record, field);

  if (operator === "!=") {
    return !values.some((value) => matchPattern(String(value), expected, "exact"));
  }

  if (operator === ":" || operator === "=") {
    const mode = operator === ":" ? "contains" : "exact";
    return values.some((value) => matchPattern(String(value), expected, mode));
  }

  return values.some((value) => compareOrdered(value, expected, operator));
}

function evaluateIn(record: SocEvent, field: string, expectedValues: string[]) {
  const values = getFieldValues(record, field);
  return values.some((value) => expectedValues.some((expected) => matchPattern(String(value), expected, "exact")));
}

function hasValue(value: Scalar) {
  return String(value).trim().length > 0;
}

function compareOrdered(actual: Scalar, expected: string, operator: ">" | ">=" | "<" | "<=") {
  const actualNumber = typeof actual === "number" ? actual : Number(actual);
  const expectedNumber = Number(expected);
  let left: number;
  let right: number;

  if (Number.isFinite(actualNumber) && Number.isFinite(expectedNumber)) {
    left = actualNumber;
    right = expectedNumber;
  } else {
    const actualDate = Date.parse(String(actual));
    const expectedDate = Date.parse(expected);
    if (!Number.isFinite(actualDate) || !Number.isFinite(expectedDate)) return false;
    left = actualDate;
    right = expectedDate;
  }

  if (operator === ">") return left > right;
  if (operator === ">=") return left >= right;
  if (operator === "<") return left < right;
  return left <= right;
}

function matchPattern(actual: string, expected: string, mode: "contains" | "exact") {
  const actualLower = actual.toLowerCase();
  const expectedLower = expected.toLowerCase();

  if (expected.includes("*") || expected.includes("?")) {
    const expression = expected
      .replace(/[.+^${}()|[\]\\]/g, "\\$&")
      .replace(/\*/g, ".*")
      .replace(/\?/g, ".");
    return new RegExp(`^${expression}$`, "i").test(actual);
  }

  return mode === "contains" ? actualLower.includes(expectedLower) : actualLower === expectedLower;
}

function recordSearchText(record: SocEvent) {
  return flattenValues(record).map(({ value }) => String(value)).join(" ").toLowerCase();
}

function getFieldValues(record: SocEvent, field: string) {
  const normalizedField = normalizeName(field);
  const aliases = (FIELD_ALIASES[normalizedField] ?? [field]).map(normalizePath);
  const fieldIsPath = field.includes(".");

  return flattenValues(record)
    .filter(({ path }) => {
      const normalizedPath = normalizePath(path);
      if (fieldIsPath) return aliases.includes(normalizedPath);
      const lastSegment = normalizeName(path.split(".").at(-1) ?? path);
      return aliases.some((alias) => normalizedPath === alias || (!alias.includes(".") && lastSegment === alias));
    })
    .map(({ value }) => value);
}

function normalizeName(value: string) {
  return value.toLowerCase().replace(/[\s_-]/g, "");
}

function normalizePath(value: string) {
  return value.split(".").map(normalizeName).join(".");
}

function flattenValues(value: unknown, path = "", output: Array<{ path: string; value: Scalar }> = [], depth = 0) {
  if (value === null || value === undefined || depth > 8) return output;

  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
    if (path) output.push({ path, value });
    return output;
  }

  if (Array.isArray(value)) {
    for (const item of value) flattenValues(item, path, output, depth + 1);
    return output;
  }

  if (typeof value === "object") {
    for (const [key, child] of Object.entries(value)) {
      flattenValues(child, path ? `${path}.${key}` : key, output, depth + 1);
    }
  }

  return output;
}
