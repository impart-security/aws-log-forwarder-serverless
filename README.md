
# AWS log forwarder serverless

Lambda function to stream ec2 loadbalancer access logs and cloudwatch logs without hosting local impart inspector service.

## Logstream ingestion configuration

1. Create logstream access token. Open https://console.impartsecurity.net/orgs/_/settings/tokens => New API acces token => select scopes: `read:inspector_settings`, `write:inspector_metrics`, `write:org_logstream`
2. Add access token to the aws parameter store or secret manager
3. Create a [Log Binding](https://console.impartsecurity.net/orgs/_/log-bindings).
   Specify grok pattern for the expected log format.

   The following fields are supported and required to be resolved:

   - timestamp - request timestamp, `HTTPDATE` and `TIMESTAMP_ISO8601` time formats are supported automatically. For custom time format provide layout in the grok: `%{GREEDYDATA:timestamp:ts-"2006-01-02 15:04:05.000"}`
   - request - request url. Can include query string parameters if available
   - response_code - response status code
   - http_method - request http method

4. Configure aws forwarder lambda function with the environment variables:
```
ACCESS_TOKEN_PARAMETER_NAME: "<parameter store name from the step(2)>"
LOGSTREAM_ID: "<from the logbinding setup step(3)>"
```
or
```
ACCESS_TOKEN_SECRET_NAME: "<secrets manager secret name from the step(2)>" 
LOGSTREAM_ID: "<from the logbinding setup step(3)>"
```

### Grok Examples

For elb access logs:

```
%{TIMESTAMP_ISO8601:timestamp} %{NOTSPACE:loadbalancer} %{IP:client_ip}:%{NUMBER:client_port} (?:%{IP:backend_ip}:%{NUMBER:backend_port}|-) %{NUMBER:request_processing_time} %{NUMBER:backend_processing_time} %{NUMBER:response_processing_time} (?:%{NUMBER:response_code}|-) (?:%{NUMBER:backend_status_code}|-) %{NUMBER:received_bytes} %{NUMBER:sent_bytes} "(?:%{WORD:http_method}|-) (?:%{GREEDYDATA:request}|-) (?:HTTP/%{NUMBER:http_version}|-( )?)" "%{DATA:user_agent}"( %{NOTSPACE:ssl_cipher} %{NOTSPACE:ssl_protocol})?
```

For api gateway cloudwatch access logs if the log format set to:

```
$context.requestTime "$context.httpMethod $context.path $context.protocol" $context.status $context.identity.sourceIp $context.requestId
```

```
%{HTTPDATE:timestamp} "(?:%{WORD:http_method}|-) (?:%{GREEDYDATA:request}|-) (?:HTTP/%{NUMBER:http_version}|-( )?)" (?:%{NUMBER:response_code}|-)
```




