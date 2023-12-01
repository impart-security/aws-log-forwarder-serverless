import { SSMClient, GetParameterCommand } from "@aws-sdk/client-ssm";
import { SecretsManagerClient, GetSecretValueCommand } from "@aws-sdk/client-secrets-manager";
import { GetObjectCommand, S3Client } from "@aws-sdk/client-s3";
import axios from "axios";
import zlib from "zlib";
import util from "util";
import readline from "readline";
import {Stream} from 'stream';

const gunzip = util.promisify(zlib.gunzip);
const apiBaseUrl = process.env.API_BASE_URL ?? "https://api.impartsecurity.net/v0";
const accessTokenParameter = process.env.ACCESS_TOKEN_PARAMETER_NAME;
const accessTokenSecret = process.env.ACCESS_TOKEN_SECRET_NAME;

const EventTypes = {
  CloudWatch: 0,
  S3: 1,
}

if (!accessTokenParameter && !accessTokenSecret) {
  const err = "missing ACCESS_TOKEN_PARAMETER_NAME or ACCESS_TOKEN_SECRET_NAME env variable";
  console.log(err);
  process.exit(-1);
}

const fetchParameter = async () => {
  const ssmClient = new SSMClient({ })
  const command = new GetParameterCommand({ Name: accessTokenParameter, WithDecryption: true });
  const response = await ssmClient.send(command);
  return response.Parameter.Value;
}

const fetchSecret = async () => {
  const secretsManagerClient = new SecretsManagerClient({ })
  const command = new GetSecretValueCommand({
    SecretId: accessTokenSecret
  });
  const response = await secretsManagerClient.send(command);
  return response.SecretString;
}

const accessToken = accessTokenParameter? await fetchParameter() : await fetchSecret();

export const handler = async (event, context, callback) => {
  let logstreamId = process.env.LOGSTREAM_ID;

  const arr = accessToken.split(".");
  if (arr.length < 2){
    console.log("invalid access token value");
    callback("invalid access token value");
    return;
  }

  const decoded = JSON.parse(
    Buffer.from(arr[1], "base64").toString()
  );
  const orgId = decoded.sub.substring("4");
  const readableStream = new Stream.Readable( {
    read( ) { }
  })

  let lineCount = 0;
  let parsedRequest = null;
  let eventType = 0;
  if (event.awslogs) {
    eventType = EventTypes.CloudWatch;
    console.log("awslogs event");
    const payload = new Buffer.from(event.awslogs.data, "base64");
    const result = await gunzip(payload);
    parsedRequest = JSON.parse(result.toString("utf8"));
    if (!logstreamId){
      logstreamId = encodeURIComponent(`${parsedRequest.owner}:${parsedRequest.logGroup}`);
    }
  } else if (event.Records[0].s3) {
    eventType = EventTypes.S3;
    console.log(`S3 bucket: ${event.Records[0].s3.bucket.name}`);
    if (!logstreamId){
      logstreamId = encodeURIComponent(`${event.Records[0].s3.bucket.name}`);
    }
  }
  else {
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
  const promise = axios.post(url, readableStream, {
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type': 'application/octet-stream',
      'User-Agent': 'aws-lambda-forwarder'
    },
  }).then(() => {
    console.log(`sent ${lineCount} lines for inspection`);
    callback(null, `sent ${lineCount} lines for inspection`);
  }).catch(function (error) {
    console.log(error.response.status);
    console.log(error.response.data);
    callback(error.response.data)
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

      readableStream.push(null);//end of stream
      break;
    }
    case EventTypes.S3: {
      const bucket = event.Records[0].s3.bucket.name;
      const key = decodeURIComponent(
        event.Records[0].s3.object.key.replace(/\+/g, " "),
      );

      // Retrieve S3 Object
      const s3Client = new S3Client();
      const getObjectCommand = new GetObjectCommand({
        Bucket: bucket,
        Key: key,
      });

      const response = await s3Client.send(getObjectCommand);
      const lineReader = readline.createInterface({
        input: response.Body.pipe(zlib.createGunzip()),
      });

      lineReader.on("line", (line) => {
        if (line[0] !== "#") {
          readableStream.push(line + "\n");
          ++lineCount;
        }
      });

      lineReader.on("close", () => {
        readableStream.push(null);//end of stream
      });
      break;
    }
    default:
      callback("unknown event type");
  }

  await promise;
};
