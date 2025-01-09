import { GetObjectCommand, S3Client } from "@aws-sdk/client-s3";
import {
  GetSecretValueCommand,
  SecretsManagerClient,
} from "@aws-sdk/client-secrets-manager";
import { GetParameterCommand, SSMClient } from "@aws-sdk/client-ssm";
import axios from "axios";
import readline from "readline";
import { Readable, Stream } from "stream";
import util from "util";
import zlib from "zlib";

const gunzip = util.promisify(zlib.gunzip);
const apiBaseUrl =
  process.env["API_BASE_URL"] ?? "https://api.impartsecurity.net/v0";
const accessTokenParameter = process.env["ACCESS_TOKEN_PARAMETER_NAME"];
const accessTokenSecret = process.env["ACCESS_TOKEN_SECRET_NAME"];

const EventTypes = {
  CloudWatch: 0,
  S3: 1,
};

if (!accessTokenParameter && !accessTokenSecret) {
  const err =
    "missing ACCESS_TOKEN_PARAMETER_NAME or ACCESS_TOKEN_SECRET_NAME env variable";
  console.log(err);
  process.exit(-1);
}

const fetchParameter = async () => {
  const ssmClient = new SSMClient({});
  const command = new GetParameterCommand({
    Name: accessTokenParameter,
    WithDecryption: true,
  });
  const response = await ssmClient.send(command);
  if (!response.Parameter || !response.Parameter.Value) {
    throw new Error("invalid parameter value");
  }

  return response.Parameter.Value;
};

const fetchSecret = async () => {
  const secretsManagerClient = new SecretsManagerClient({});
  const command = new GetSecretValueCommand({
    SecretId: accessTokenSecret,
  });
  const response = await secretsManagerClient.send(command);
  return response.SecretString;
};

const accessToken = accessTokenParameter
  ? await fetchParameter()
  : await fetchSecret();

/**
 * AWS Lambda handler
 * @param { {awslogs?: {data: string}, Records: {s3?: {bucket: {name:string}, object: {key: string}}}[] } } event - The event object
 * @param {Object} _context - The context object
 * @param {Function} callback - The callback function
 */
export const handler = async (event, _context, callback) => {
  let logstreamId = process.env["LOGSTREAM_ID"];

  const arr = (accessToken ?? "").split(".");
  if (arr.length < 2) {
    console.log("invalid access token value");
    callback("invalid access token value");
    return;
  }

  const encodedToken = arr[1];
  if (!encodedToken) {
    console.log("invalid access token value");
    callback("invalid access token value");
    return;
  }

  const decoded = JSON.parse(Buffer.from(encodedToken, "base64").toString());
  const orgId = decoded.sub.substring("4");
  const readableStream = new Stream.Readable({
    read() {},
  });

  const record = event.Records[0];

  let lineCount = 0;
  let parsedRequest = null;
  let eventType = 0;
  if (event.awslogs) {
    eventType = EventTypes.CloudWatch;
    console.log("awslogs event");
    const payload = Buffer.from(event.awslogs.data, "base64");
    const result = await gunzip(payload);
    parsedRequest = JSON.parse(result.toString("utf8"));
    if (!logstreamId) {
      logstreamId = encodeURIComponent(
        `${parsedRequest.owner}:${parsedRequest.logGroup}`,
      );
    }
  } else if (!!record && !!record.s3) {
    eventType = EventTypes.S3;
    console.log(`S3 bucket: ${record.s3.bucket.name}`);
    if (!logstreamId) {
      logstreamId = record.s3.bucket.name;
      if (!record.s3.object.key.startsWith("AWSLogs/")) {
        let prefix = record.s3.object.key.split("/AWSLogs/")[0];
        logstreamId = `${logstreamId}/${prefix}`;
      }
    }
    logstreamId = encodeURIComponent(logstreamId);
  } else {
    callback("unsupported event type");
    return;
  }

  if (!logstreamId) {
    const err = "missing LOGSTREAM_ID env variable";
    console.log(err);
    callback(err);
    return;
  }

  const url = `${apiBaseUrl}/orgs/${orgId}/logstream/${logstreamId}`;

  //initiate send stream request
  const promise = axios
    .post(url, readableStream, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/octet-stream",
        "User-Agent": "aws-lambda-forwarder",
      },
    })
    .then(() => {
      console.log(`sent ${lineCount} lines for inspection`);
      callback(null, `sent ${lineCount} lines for inspection`);
    })
    .catch(function (error) {
      console.log(error.response.status);
      console.log(error.response.data);
      callback(error.response.data);
    });

  switch (eventType) {
    case EventTypes.CloudWatch: {
      for (let i = 0; i < parsedRequest.logEvents.length; i++) {
        if (
          parsedRequest.logEvents[i].message.length &&
          parsedRequest.logEvents[i].message[0] === "#"
        ) {
          continue;
        }

        const message = parsedRequest.logEvents[i].message.endsWith("\n")
          ? parsedRequest.logEvents[i].message
          : parsedRequest.logEvents[i].message + "\n";

        readableStream.push(message);
        ++lineCount;
      }

      readableStream.push(null); //end of stream
      break;
    }
    case EventTypes.S3: {
      if (!record || !record.s3) {
        callback("missing s3 record");
        return;
      }

      const bucket = record.s3.bucket.name;
      const key = decodeURIComponent(record.s3.object.key.replace(/\+/g, " "));

      // Retrieve S3 Object
      const s3Client = new S3Client();
      const getObjectCommand = new GetObjectCommand({
        Bucket: bucket,
        Key: key,
      });

      const response = await s3Client.send(getObjectCommand);
      if (!response.Body) {
        callback("no body in S3 object");
        return;
      }

      /** @type {Readable} */
      let body;

      // Check if body is a Blob and convert it to ReadableStream
      if (response.Body instanceof Blob) {
        const readableStream = response.Body.stream();
        body = Readable.from(readableStream);
      } else if (response.Body instanceof Readable) {
        body = response.Body;
      } else {
        callback(
          "Unexpected body type: response.Body is not a compatible stream type.",
        );
        return;
      }

      const lineReader = readline.createInterface({
        input: body.pipe(zlib.createGunzip()),
      });

      lineReader.on("line", (line) => {
        if (line[0] !== "#") {
          readableStream.push(line + "\n");
          ++lineCount;
        }
      });

      lineReader.on("close", () => {
        readableStream.push(null); //end of stream
      });
      break;
    }
    default:
      callback("unknown event type");
  }

  await promise;
};
