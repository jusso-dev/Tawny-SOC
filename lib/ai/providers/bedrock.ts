import { createHash, createHmac } from "node:crypto";
import type { AiProvider, BedrockConfig } from "@/lib/ai/types";

type ConverseResponse = {
  output?: { message?: { content?: Array<{ text?: string }> } };
  usage?: { inputTokens?: number; outputTokens?: number };
};

export type AwsSignInput = {
  method: string;
  host: string;
  canonicalUri: string;
  canonicalQuery: string;
  headers: Record<string, string>;
  payload: string;
  region: string;
  service: string;
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
  date: Date;
};

function sha256Hex(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function hmac(key: Buffer | string, value: string): Buffer {
  return createHmac("sha256", key).update(value, "utf8").digest();
}

export function rfc3986Encode(value: string): string {
  return encodeURIComponent(value).replace(/[!'()*]/g, (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`);
}

/**
 * AWS Signature Version 4. Returns the headers to send, including Authorization.
 * canonicalUri must already be encoded per the target service's rules
 * (double-encoded segments for everything except S3).
 */
export function signAwsRequest(input: AwsSignInput): Record<string, string> {
  const amzDate = input.date.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
  const dateStamp = amzDate.slice(0, 8);
  const scope = `${dateStamp}/${input.region}/${input.service}/aws4_request`;

  const headers: Record<string, string> = {
    ...input.headers,
    host: input.host,
    "x-amz-date": amzDate,
    ...(input.sessionToken ? { "x-amz-security-token": input.sessionToken } : {}),
  };

  const sortedHeaderNames = Object.keys(headers).map((name) => name.toLowerCase()).sort();
  const canonicalHeaders = sortedHeaderNames.map((name) => {
    const value = headers[Object.keys(headers).find((key) => key.toLowerCase() === name) ?? name];
    return `${name}:${String(value).trim().replace(/\s+/g, " ")}\n`;
  }).join("");
  const signedHeaders = sortedHeaderNames.join(";");

  const canonicalRequest = [
    input.method.toUpperCase(),
    input.canonicalUri,
    input.canonicalQuery,
    canonicalHeaders,
    signedHeaders,
    sha256Hex(input.payload),
  ].join("\n");

  const stringToSign = [
    "AWS4-HMAC-SHA256",
    amzDate,
    scope,
    sha256Hex(canonicalRequest),
  ].join("\n");

  const kDate = hmac(`AWS4${input.secretAccessKey}`, dateStamp);
  const kRegion = hmac(kDate, input.region);
  const kService = hmac(kRegion, input.service);
  const kSigning = hmac(kService, "aws4_request");
  const signature = createHmac("sha256", kSigning).update(stringToSign, "utf8").digest("hex");

  return {
    ...headers,
    authorization: `AWS4-HMAC-SHA256 Credential=${input.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`,
  };
}

export function createBedrockProvider(config: BedrockConfig, timeoutMs = 60_000): AiProvider {
  return {
    id: "aws-bedrock",
    label: "AWS Bedrock",
    async complete(request) {
      if (!config.region || !config.modelId) throw new Error("Bedrock region and model ID are required.");
      if (!config.accessKeyId || !config.secretAccessKey) throw new Error("Bedrock AWS credentials are not configured.");

      const systemText = request.messages.filter((message) => message.role === "system").map((message) => message.content).join("\n\n");
      const conversation = request.messages
        .filter((message) => message.role !== "system")
        .map((message) => ({ role: message.role as "user" | "assistant", content: [{ text: message.content }] }));
      if (!conversation.length) throw new Error("Bedrock requires at least one user message.");

      const payload = JSON.stringify({
        ...(systemText ? { system: [{ text: systemText }] } : {}),
        messages: conversation,
        inferenceConfig: {
          maxTokens: request.maxTokens ?? 1024,
          ...(request.temperature !== undefined ? { temperature: request.temperature } : {}),
        },
      });

      const host = `bedrock-runtime.${config.region}.amazonaws.com`;
      const encodedModelId = rfc3986Encode(config.modelId);
      const path = `/model/${encodedModelId}/converse`;
      // SigV4 double-encodes path segments for every service except S3.
      const canonicalUri = `/model/${rfc3986Encode(encodedModelId)}/converse`;

      const signedHeaders = signAwsRequest({
        method: "POST",
        host,
        canonicalUri,
        canonicalQuery: "",
        headers: { "content-type": "application/json" },
        payload,
        region: config.region,
        service: "bedrock",
        accessKeyId: config.accessKeyId,
        secretAccessKey: config.secretAccessKey,
        sessionToken: config.sessionToken || undefined,
        date: new Date(),
      });

      const started = Date.now();
      const res = await fetch(`https://${host}${path}`, {
        method: "POST",
        headers: signedHeaders,
        body: payload,
        signal: AbortSignal.timeout(timeoutMs),
      });

      if (!res.ok) {
        const detail = await res.text().catch(() => "");
        throw new Error(`AWS Bedrock returned HTTP ${res.status}${detail ? `: ${detail.slice(0, 300)}` : ""}`);
      }

      const body = await res.json() as ConverseResponse;
      const text = body.output?.message?.content?.map((block) => block.text ?? "").join("") ?? "";
      if (!text) throw new Error("AWS Bedrock returned an empty completion.");

      return {
        text,
        provider: "aws-bedrock" as const,
        model: config.modelId,
        inputTokens: body.usage?.inputTokens,
        outputTokens: body.usage?.outputTokens,
        latencyMs: Date.now() - started,
      };
    },
  };
}
