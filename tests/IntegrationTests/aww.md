{ util: 
       { engine: [Function: engine],
         userAgent: [Function: userAgent],
         isBrowser: [Function: isBrowser],
         isNode: [Function: isNode],
         uriEscape: [Function: uriEscape],
         uriEscapePath: [Function: uriEscapePath],
         urlParse: [Function: urlParse],
         urlFormat: [Function: urlFormat],
         queryStringParse: [Function: queryStringParse],
         queryParamsToString: [Function: queryParamsToString],
         readFileSync: [Function: readFileSync],
         base64: { encode: [Function: encode64], decode: [Function: decode64] },
         buffer: { toStream: [Function: toStream], concat: [Function] },
         string: 
          { byteLength: [Function: byteLength],
            upperFirst: [Function: upperFirst],
            lowerFirst: [Function: lowerFirst] },
         ini: { parse: [Function: string] },
         fn: { noop: [Function], makeAsync: [Function: makeAsync] },
         date: 
          { getDate: [Function: getDate],
            iso8601: [Function: iso8601],
            rfc822: [Function: rfc822],
            unixTimestamp: [Function: unixTimestamp],
            from: [Function: format],
            format: [Function: format],
            parseTimestamp: [Function: parseTimestamp] },
         crypto: 
          { crc32Table: [Object],
            crc32: [Function: crc32],
            hmac: [Function: hmac],
            md5: [Function: md5],
            sha256: [Function: sha256],
            hash: [Function],
            toHex: [Function: toHex],
            createHash: [Function: createHash],
            lib: [Object] },
         abort: {},
         each: [Function: each],
         arrayEach: [Function: arrayEach],
         update: [Function: update],
         merge: [Function: merge],
         copy: [Function: copy],
         isEmpty: [Function: isEmpty],
         arraySliceFn: [Function: arraySliceFn],
         isType: [Function: isType],
         typeName: [Function: typeName],
         error: [Function: error],
         inherit: [Function: inherit],
         mixin: [Function: mixin],
         hideProperties: [Function: hideProperties],
         property: [Function: property],
         memoizedProperty: [Function: memoizedProperty],
         hoistPayloadMember: [Function: hoistPayloadMember],
         computeSha256: [Function: computeSha256],
         isClockSkewed: [Function: isClockSkewed],
         applyClockOffset: [Function: applyClockOffset],
         extractRequestId: [Function: extractRequestId],
         addPromises: [Function: addPromises],
         promisifyMethod: [Function: promisifyMethod],
         isDualstackAvailable: [Function: isDualstackAvailable],
         calculateRetryDelay: [Function: calculateRetryDelay],
         handleRequestWithRetries: [Function: handleRequestWithRetries],
         Buffer: 
          { [Function: Buffer]
            poolSize: 8192,
            isBuffer: [Function: isBuffer],
            compare: [Function: compare],
            isEncoding: [Function],
            concat: [Function],
            byteLength: [Function: byteLength] },
         domain: 
          { _stack: [],
            Domain: [Object],
            createDomain: [Function],
            create: [Function],
            active: null },
         stream: 
          { [Function: Stream]
            super_: [Object],
            Readable: [Object],
            Writable: [Object],
            Duplex: [Object],
            Transform: [Object],
            PassThrough: [Object],
            Stream: [Circular] },
         url: 
          { parse: [Function: urlParse],
            resolve: [Function: urlResolve],
            resolveObject: [Function: urlResolveObject],
            format: [Function: urlFormat],
            Url: [Function: Url] },
         querystring: 
          { unescapeBuffer: [Function],
            unescape: [Function],
            escape: [Function],
            encode: [Function],
            stringify: [Function],
            decode: [Function],
            parse: [Function] } },
      VERSION: '2.7.21',
      Signers: 
       { RequestSigner: 
          { [Function: RequestSigner]
            __super__: [Function: Object],
            getVersion: [Function: getVersion] },
         V2: { [Function] __super__: [Object] },
         V3: { [Function] __super__: [Object] },
         V3Https: { [Function] __super__: [Object] },
         V4: { [Function: V4] __super__: [Object] },
         S3: { [Function] __super__: [Object] },
         Presign: { [Function] __super__: [Function: Object] } },
      Protocol: 
       { Json: 
          { buildRequest: [Function: buildRequest],
            extractError: [Function: extractError],
            extractData: [Function: extractData] },
         Query: 
          { buildRequest: [Function: buildRequest],
            extractError: [Function: extractError],
            extractData: [Function: extractData] },
         Rest: 
          { buildRequest: [Function: buildRequest],
            extractError: [Function: extractError],
            extractData: [Function: extractData],
            generateURI: [Function: generateURI] },
         RestJson: 
          { buildRequest: [Function: buildRequest],
            extractError: [Function: extractError],
            extractData: [Function: extractData] },
         RestXml: 
          { buildRequest: [Function: buildRequest],
            extractError: [Function: extractError],
            extractData: [Function: extractData] } },
      XML: 
       { Builder: [Function: XmlBuilder],
         Parser: [Function: NodeXmlParser] },
      JSON: 
       { Builder: [Function: JsonBuilder],
         Parser: [Function: JsonParser] },
      Model: 
       { Api: [Function: Api],
         Operation: [Function: Operation],
         Shape: 
          { [Function: Shape]
            normalizedTypes: [Object],
            types: [Object],
            resolve: [Function: resolve],
            create: [Function: create],
            shapes: [Object] },
         Paginator: [Function: Paginator],
         ResourceWaiter: [Function: ResourceWaiter] },
      apiLoader: 
       { [Function]
         services: 
          { sts: [Object],
            cognitoidentity: [Object],
            acm: [Object],
            apigateway: [Object],
            applicationautoscaling: [Object],
            appstream: [Object],
            autoscaling: [Object],
            batch: [Object],
            budgets: [Object],
            cloudformation: [Object],
            cloudfront: [Object],
            cloudhsm: [Object],
            cloudsearch: [Object],
            cloudsearchdomain: [Object],
            cloudtrail: [Object],
            cloudwatch: [Object],
            cloudwatchevents: [Object],
            cloudwatchlogs: [Object],
            codebuild: [Object],
            codecommit: [Object],
            codedeploy: [Object],
            codepipeline: [Object],
            cognitoidentityserviceprovider: [Object],
            cognitosync: [Object],
            configservice: [Object],
            datapipeline: [Object],
            devicefarm: [Object],
            directconnect: [Object],
            directoryservice: [Object],
            discovery: [Object],
            dms: [Object],
            dynamodb: [Object],
            dynamodbstreams: [Object],
            ec2: [Object],
            ecr: [Object],
            ecs: [Object],
            efs: [Object],
            elasticache: [Object],
            elasticbeanstalk: [Object],
            elb: [Object],
            elbv2: [Object],
            emr: [Object],
            es: [Object],
            elastictranscoder: [Object],
            firehose: [Object],
            gamelift: [Object],
            glacier: [Object],
            health: [Object],
            iam: [Object],
            importexport: [Object],
            inspector: [Object],
            iot: [Object],
            iotdata: [Object],
            kinesis: [Object],
            kinesisanalytics: [Object],
            kms: [Object],
            lambda: [Object],
            lightsail: [Object],
            machinelearning: [Object],
            marketplacecommerceanalytics: [Object],
            marketplacemetering: [Object],
            mobileanalytics: [Object],
            opsworks: [Object],
            opsworkscm: [Object],
            pinpoint: [Object],
            polly: [Object],
            rds: [Object],
            redshift: [Object],
            rekognition: [Object],
            route53: [Object],
            route53domains: [Object],
            s3: [Object],
            servicecatalog: [Object],
            ses: [Object],
            shield: [Object],
            simpledb: [Object],
            sms: [Object],
            snowball: [Object],
            sns: [Object],
            sqs: [Object],
            ssm: [Object],
            storagegateway: [Object],
            stepfunctions: [Object],
            support: [Object],
            swf: [Object],
            xray: [Object],
            waf: [Object],
            wafregional: [Object],
            workspaces: [Object] } },
      Service: 
       { [Function: Service]
         __super__: [Function: Object],
         defineMethods: [Function: defineMethods],
         defineService: [Function: defineService],
         addVersions: [Function: addVersions],
         defineServiceApi: [Function: defineServiceApi],
         hasService: [Function],
         _serviceMap: 
          { sts: true,
            cognitoidentity: true,
            acm: true,
            apigateway: true,
            applicationautoscaling: true,
            appstream: true,
            autoscaling: true,
            batch: true,
            budgets: true,
            cloudformation: true,
            cloudfront: true,
            cloudhsm: true,
            cloudsearch: true,
            cloudsearchdomain: true,
            cloudtrail: true,
            cloudwatch: true,
            cloudwatchevents: true,
            cloudwatchlogs: true,
            codebuild: true,
            codecommit: true,
            codedeploy: true,
            codepipeline: true,
            cognitoidentityserviceprovider: true,
            cognitosync: true,
            configservice: true,
            datapipeline: true,
            devicefarm: true,
            directconnect: true,
            directoryservice: true,
            discovery: true,
            dms: true,
            dynamodb: true,
            dynamodbstreams: true,
            ec2: true,
            ecr: true,
            ecs: true,
            efs: true,
            elasticache: true,
            elasticbeanstalk: true,
            elb: true,
            elbv2: true,
            emr: true,
            es: true,
            elastictranscoder: true,
            firehose: true,
            gamelift: true,
            glacier: true,
            health: true,
            iam: true,
            importexport: true,
            inspector: true,
            iot: true,
            iotdata: true,
            kinesis: true,
            kinesisanalytics: true,
            kms: true,
            lambda: true,
            lightsail: true,
            machinelearning: true,
            marketplacecommerceanalytics: true,
            marketplacemetering: true,
            mobileanalytics: true,
            opsworks: true,
            opsworkscm: true,
            pinpoint: true,
            polly: true,
            rds: true,
            redshift: true,
            rekognition: true,
            route53: true,
            route53domains: true,
            s3: true,
            servicecatalog: true,
            ses: true,
            shield: true,
            simpledb: true,
            sms: true,
            snowball: true,
            sns: true,
            sqs: true,
            ssm: true,
            storagegateway: true,
            stepfunctions: true,
            support: true,
            swf: true,
            xray: true,
            waf: true,
            wafregional: true,
            workspaces: true } },
      Credentials: 
       { [Function: Credentials]
         __super__: [Function: Object],
         addPromisesToClass: [Function: addPromisesToClass],
         deletePromisesFromClass: [Function: deletePromisesFromClass] },
      CredentialProviderChain: 
       { [Function: CredentialProviderChain]
         __super__: 
          { [Function: Credentials]
            __super__: [Function: Object],
            addPromisesToClass: [Function: addPromisesToClass],
            deletePromisesFromClass: [Function: deletePromisesFromClass] },
         defaultProviders: [ [Function], [Function], [Function], [Function] ],
         addPromisesToClass: [Function: addPromisesToClass],
         deletePromisesFromClass: [Function: deletePromisesFromClass] },
      Config: { [Function: Config] __super__: [Function: Object] },
      config: 
       Config {
         credentials: 
          SharedIniFileCredentials {
            expired: false,
            expireTime: null,
            accessKeyId: 'AKIAI6QYQRDZAB6JKWUQ',
            sessionToken: undefined,
            filename: '/Users/perrybirch/.aws/credentials',
            profile: 'default',
            disableAssumeRole: true },
         credentialProvider: CredentialProviderChain { providers: [Object] },
         region: undefined,
         logger: null,
         apiVersions: {},
         apiVersion: null,
         endpoint: undefined,
         httpOptions: { timeout: 120000 },
         maxRetries: undefined,
         maxRedirects: 10,
         paramValidation: true,
         sslEnabled: true,
         s3ForcePathStyle: false,
         s3BucketEndpoint: false,
         s3DisableBodySigning: true,
         computeChecksums: true,
         convertResponseTypes: true,
         correctClockSkew: false,
         customUserAgent: null,
         dynamoDbCrc32: true,
         systemClockOffset: 0,
         signatureVersion: null,
         signatureCache: true,
         retryDelayOptions: { base: 100 },
         useAccelerateEndpoint: false },
      STS: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2011-06-15': null },
         apiVersions: [ '2011-06-15' ],
         serviceIdentifier: 'sts' },
      TemporaryCredentials: 
       { [Function: TemporaryCredentials]
         __super__: 
          { [Function: Credentials]
            __super__: [Function: Object],
            addPromisesToClass: [Function: addPromisesToClass],
            deletePromisesFromClass: [Function: deletePromisesFromClass] } },
      WebIdentityCredentials: 
       { [Function: WebIdentityCredentials]
         __super__: 
          { [Function: Credentials]
            __super__: [Function: Object],
            addPromisesToClass: [Function: addPromisesToClass],
            deletePromisesFromClass: [Function: deletePromisesFromClass] } },
      CognitoIdentity: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2014-06-30': null },
         apiVersions: [ '2014-06-30' ],
         serviceIdentifier: 'cognitoidentity' },
      CognitoIdentityCredentials: 
       { [Function: CognitoIdentityCredentials]
         __super__: 
          { [Function: Credentials]
            __super__: [Function: Object],
            addPromisesToClass: [Function: addPromisesToClass],
            deletePromisesFromClass: [Function: deletePromisesFromClass] } },
      SAMLCredentials: 
       { [Function: SAMLCredentials]
         __super__: 
          { [Function: Credentials]
            __super__: [Function: Object],
            addPromisesToClass: [Function: addPromisesToClass],
            deletePromisesFromClass: [Function: deletePromisesFromClass] } },
      Endpoint: { [Function: Endpoint] __super__: [Function: Object] },
      HttpRequest: { [Function: HttpRequest] __super__: [Function: Object] },
      HttpResponse: { [Function: HttpResponse] __super__: [Function: Object] },
      HttpClient: 
       { [Function]
         __super__: [Function: Object],
         getInstance: [Function: getInstance],
         streamsApiVersion: 2 },
      SequentialExecutor: { [Function: SequentialExecutor] __super__: [Function: Object] },
      EventListeners: 
       { Core: 
          SequentialExecutor {
            _events: [Object],
            VALIDATE_CREDENTIALS: [Object],
            VALIDATE_REGION: [Function: VALIDATE_REGION],
            BUILD_IDEMPOTENCY_TOKENS: [Function: BUILD_IDEMPOTENCY_TOKENS],
            VALIDATE_PARAMETERS: [Function: VALIDATE_PARAMETERS],
            COMPUTE_SHA256: [Object],
            SET_CONTENT_LENGTH: [Function: SET_CONTENT_LENGTH],
            SET_HTTP_HOST: [Function: SET_HTTP_HOST],
            RESTART: [Function: RESTART],
            SIGN: [Object],
            VALIDATE_RESPONSE: [Function: VALIDATE_RESPONSE],
            SEND: [Object],
            HTTP_HEADERS: [Function: HTTP_HEADERS],
            HTTP_DATA: [Function: HTTP_DATA],
            HTTP_DONE: [Function: HTTP_DONE],
            FINALIZE_ERROR: [Function: FINALIZE_ERROR],
            INVALIDATE_CREDENTIALS: [Function: INVALIDATE_CREDENTIALS],
            EXPIRED_SIGNATURE: [Function: EXPIRED_SIGNATURE],
            CLOCK_SKEWED: [Function: CLOCK_SKEWED],
            REDIRECT: [Function: REDIRECT],
            RETRY_CHECK: [Function: RETRY_CHECK],
            RESET_RETRY_STATE: [Object] },
         CorePost: 
          SequentialExecutor {
            _events: [Object],
            EXTRACT_REQUEST_ID: [Function: extractRequestId],
            ENOTFOUND_ERROR: [Function: ENOTFOUND_ERROR] },
         Logger: SequentialExecutor { _events: [Object], LOG_REQUEST: [Function: LOG_REQUEST] },
         Json: 
          SequentialExecutor {
            _events: [Object],
            BUILD: [Function: buildRequest],
            EXTRACT_DATA: [Function: extractData],
            EXTRACT_ERROR: [Function: extractError] },
         Rest: 
          SequentialExecutor {
            _events: [Object],
            BUILD: [Function: buildRequest],
            EXTRACT_DATA: [Function: extractData],
            EXTRACT_ERROR: [Function: extractError] },
         RestJson: 
          SequentialExecutor {
            _events: [Object],
            BUILD: [Function: buildRequest],
            EXTRACT_DATA: [Function: extractData],
            EXTRACT_ERROR: [Function: extractError] },
         RestXml: 
          SequentialExecutor {
            _events: [Object],
            BUILD: [Function: buildRequest],
            EXTRACT_DATA: [Function: extractData],
            EXTRACT_ERROR: [Function: extractError] },
         Query: 
          SequentialExecutor {
            _events: [Object],
            BUILD: [Function: buildRequest],
            EXTRACT_DATA: [Function: extractData],
            EXTRACT_ERROR: [Function: extractError] } },
      Request: 
       { [Function: Request]
         __super__: [Function: Object],
         addPromisesToClass: [Function: addPromisesToClass],
         deletePromisesFromClass: [Function: deletePromisesFromClass] },
      Response: { [Function: Response] __super__: [Function: Object] },
      ResourceWaiter: { [Function: constructor] __super__: [Function: Object] },
      ParamValidator: { [Function: ParamValidator] __super__: [Function: Object] },
      events: SequentialExecutor { _events: {} },
      NodeHttpClient: { [Function] __super__: [Function: Object] },
      MetadataService: { [Function: MetadataService] __super__: [Function: Object] },
      EC2MetadataCredentials: 
       { [Function: EC2MetadataCredentials]
         __super__: 
          { [Function: Credentials]
            __super__: [Function: Object],
            addPromisesToClass: [Function: addPromisesToClass],
            deletePromisesFromClass: [Function: deletePromisesFromClass] } },
      ECSCredentials: 
       { [Function: ECSCredentials]
         __super__: 
          { [Function: Credentials]
            __super__: [Function: Object],
            addPromisesToClass: [Function: addPromisesToClass],
            deletePromisesFromClass: [Function: deletePromisesFromClass] } },
      EnvironmentCredentials: 
       { [Function: EnvironmentCredentials]
         __super__: 
          { [Function: Credentials]
            __super__: [Function: Object],
            addPromisesToClass: [Function: addPromisesToClass],
            deletePromisesFromClass: [Function: deletePromisesFromClass] } },
      FileSystemCredentials: 
       { [Function: FileSystemCredentials]
         __super__: 
          { [Function: Credentials]
            __super__: [Function: Object],
            addPromisesToClass: [Function: addPromisesToClass],
            deletePromisesFromClass: [Function: deletePromisesFromClass] } },
      SharedIniFileCredentials: 
       { [Function: SharedIniFileCredentials]
         __super__: 
          { [Function: Credentials]
            __super__: [Function: Object],
            addPromisesToClass: [Function: addPromisesToClass],
            deletePromisesFromClass: [Function: deletePromisesFromClass] } },
      ACM: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2015-12-08': null },
         apiVersions: [ '2015-12-08' ],
         serviceIdentifier: 'acm' },
      APIGateway: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2015-07-09': null },
         apiVersions: [ '2015-07-09' ],
         serviceIdentifier: 'apigateway' },
      ApplicationAutoScaling: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2016-02-06': null },
         apiVersions: [ '2016-02-06' ],
         serviceIdentifier: 'applicationautoscaling' },
      AppStream: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2016-12-01': null },
         apiVersions: [ '2016-12-01' ],
         serviceIdentifier: 'appstream' },
      AutoScaling: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2011-01-01': null },
         apiVersions: [ '2011-01-01' ],
         serviceIdentifier: 'autoscaling' },
      Batch: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2016-08-10': null },
         apiVersions: [ '2016-08-10' ],
         serviceIdentifier: 'batch' },
      Budgets: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2016-10-20': null },
         apiVersions: [ '2016-10-20' ],
         serviceIdentifier: 'budgets' },
      CloudFormation: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2010-05-15': null },
         apiVersions: [ '2010-05-15' ],
         serviceIdentifier: 'cloudformation' },
      CloudFront: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: 
          { '2013-05-12*': null,
            '2013-11-11*': null,
            '2014-05-31*': null,
            '2014-10-21*': null,
            '2014-11-06*': null,
            '2015-04-17*': null,
            '2015-07-27*': null,
            '2015-09-17*': null,
            '2016-01-13*': null,
            '2016-01-28*': null,
            '2016-08-01*': null,
            '2016-08-20*': null,
            '2016-09-07*': null,
            '2016-09-29*': null,
            '2016-11-25': null },
         apiVersions: 
          [ '2013-05-12*',
            '2013-11-11*',
            '2014-05-31*',
            '2014-10-21*',
            '2014-11-06*',
            '2015-04-17*',
            '2015-07-27*',
            '2015-09-17*',
            '2016-01-13*',
            '2016-01-28*',
            '2016-08-01*',
            '2016-08-20*',
            '2016-09-07*',
            '2016-09-29*',
            '2016-11-25' ],
         serviceIdentifier: 'cloudfront',
         Signer: { [Function: Signer] __super__: [Function: Object] } },
      CloudHSM: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2014-05-30': null },
         apiVersions: [ '2014-05-30' ],
         serviceIdentifier: 'cloudhsm' },
      CloudSearch: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2011-02-01': null, '2013-01-01': null },
         apiVersions: [ '2011-02-01', '2013-01-01' ],
         serviceIdentifier: 'cloudsearch' },
      CloudSearchDomain: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2013-01-01': null },
         apiVersions: [ '2013-01-01' ],
         serviceIdentifier: 'cloudsearchdomain' },
      CloudTrail: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2013-11-01': null },
         apiVersions: [ '2013-11-01' ],
         serviceIdentifier: 'cloudtrail' },
      CloudWatch: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2010-08-01': null },
         apiVersions: [ '2010-08-01' ],
         serviceIdentifier: 'cloudwatch' },
      CloudWatchEvents: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2014-02-03*': null, '2015-10-07': null },
         apiVersions: [ '2014-02-03*', '2015-10-07' ],
         serviceIdentifier: 'cloudwatchevents' },
      CloudWatchLogs: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2014-03-28': null },
         apiVersions: [ '2014-03-28' ],
         serviceIdentifier: 'cloudwatchlogs' },
      CodeBuild: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2016-10-06': null },
         apiVersions: [ '2016-10-06' ],
         serviceIdentifier: 'codebuild' },
      CodeCommit: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2015-04-13': null },
         apiVersions: [ '2015-04-13' ],
         serviceIdentifier: 'codecommit' },
      CodeDeploy: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2014-10-06': null },
         apiVersions: [ '2014-10-06' ],
         serviceIdentifier: 'codedeploy' },
      CodePipeline: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2015-07-09': null },
         apiVersions: [ '2015-07-09' ],
         serviceIdentifier: 'codepipeline' },
      CognitoIdentityServiceProvider: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2016-04-18': null },
         apiVersions: [ '2016-04-18' ],
         serviceIdentifier: 'cognitoidentityserviceprovider' },
      CognitoSync: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2014-06-30': null },
         apiVersions: [ '2014-06-30' ],
         serviceIdentifier: 'cognitosync' },
      ConfigService: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2014-11-12': null },
         apiVersions: [ '2014-11-12' ],
         serviceIdentifier: 'configservice' },
      DataPipeline: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2012-10-29': null },
         apiVersions: [ '2012-10-29' ],
         serviceIdentifier: 'datapipeline' },
      DeviceFarm: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2015-06-23': null },
         apiVersions: [ '2015-06-23' ],
         serviceIdentifier: 'devicefarm' },
      DirectConnect: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2012-10-25': null },
         apiVersions: [ '2012-10-25' ],
         serviceIdentifier: 'directconnect' },
      DirectoryService: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2015-04-16': null },
         apiVersions: [ '2015-04-16' ],
         serviceIdentifier: 'directoryservice' },
      Discovery: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2015-11-01': null },
         apiVersions: [ '2015-11-01' ],
         serviceIdentifier: 'discovery' },
      DMS: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2016-01-01': null },
         apiVersions: [ '2016-01-01' ],
         serviceIdentifier: 'dms' },
      DynamoDB: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2011-12-05': null, '2012-08-10': null },
         apiVersions: [ '2011-12-05', '2012-08-10' ],
         serviceIdentifier: 'dynamodb',
         DocumentClient: { [Function: DocumentClient] __super__: [Function: Object] } },
      DynamoDBStreams: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2012-08-10': null },
         apiVersions: [ '2012-08-10' ],
         serviceIdentifier: 'dynamodbstreams' },
      EC2: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: 
          { '2013-06-15*': null,
            '2013-10-15*': null,
            '2014-02-01*': null,
            '2014-05-01*': null,
            '2014-06-15*': null,
            '2014-09-01*': null,
            '2014-10-01*': null,
            '2015-03-01*': null,
            '2015-04-15*': null,
            '2015-10-01*': null,
            '2016-04-01*': null,
            '2016-09-15*': null,
            '2016-11-15': null },
         apiVersions: 
          [ '2013-06-15*',
            '2013-10-15*',
            '2014-02-01*',
            '2014-05-01*',
            '2014-06-15*',
            '2014-09-01*',
            '2014-10-01*',
            '2015-03-01*',
            '2015-04-15*',
            '2015-10-01*',
            '2016-04-01*',
            '2016-09-15*',
            '2016-11-15' ],
         serviceIdentifier: 'ec2' },
      ECR: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2015-09-21': null },
         apiVersions: [ '2015-09-21' ],
         serviceIdentifier: 'ecr' },
      ECS: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2014-11-13': null },
         apiVersions: [ '2014-11-13' ],
         serviceIdentifier: 'ecs' },
      EFS: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2015-02-01': null },
         apiVersions: [ '2015-02-01' ],
         serviceIdentifier: 'efs' },
      ElastiCache: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: 
          { '2012-11-15*': null,
            '2014-03-24*': null,
            '2014-07-15*': null,
            '2014-09-30*': null,
            '2015-02-02': null },
         apiVersions: 
          [ '2012-11-15*',
            '2014-03-24*',
            '2014-07-15*',
            '2014-09-30*',
            '2015-02-02' ],
         serviceIdentifier: 'elasticache' },
      ElasticBeanstalk: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2010-12-01': null },
         apiVersions: [ '2010-12-01' ],
         serviceIdentifier: 'elasticbeanstalk' },
      ELB: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2012-06-01': null },
         apiVersions: [ '2012-06-01' ],
         serviceIdentifier: 'elb' },
      ELBv2: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2015-12-01': null },
         apiVersions: [ '2015-12-01' ],
         serviceIdentifier: 'elbv2' },
      EMR: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2009-03-31': null },
         apiVersions: [ '2009-03-31' ],
         serviceIdentifier: 'emr' },
      ES: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2015-01-01': null },
         apiVersions: [ '2015-01-01' ],
         serviceIdentifier: 'es' },
      ElasticTranscoder: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2012-09-25': null },
         apiVersions: [ '2012-09-25' ],
         serviceIdentifier: 'elastictranscoder' },
      Firehose: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2015-08-04': null },
         apiVersions: [ '2015-08-04' ],
         serviceIdentifier: 'firehose' },
      GameLift: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2015-10-01': null },
         apiVersions: [ '2015-10-01' ],
         serviceIdentifier: 'gamelift' },
      Glacier: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2012-06-01': null },
         apiVersions: [ '2012-06-01' ],
         serviceIdentifier: 'glacier' },
      Health: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2016-08-04': null },
         apiVersions: [ '2016-08-04' ],
         serviceIdentifier: 'health' },
      IAM: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2010-05-08': null },
         apiVersions: [ '2010-05-08' ],
         serviceIdentifier: 'iam' },
      ImportExport: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2010-06-01': null },
         apiVersions: [ '2010-06-01' ],
         serviceIdentifier: 'importexport' },
      Inspector: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2015-08-18*': null, '2016-02-16': null },
         apiVersions: [ '2015-08-18*', '2016-02-16' ],
         serviceIdentifier: 'inspector' },
      Iot: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2015-05-28': null },
         apiVersions: [ '2015-05-28' ],
         serviceIdentifier: 'iot' },
      IotData: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2015-05-28': null },
         apiVersions: [ '2015-05-28' ],
         serviceIdentifier: 'iotdata' },
      Kinesis: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2013-12-02': null },
         apiVersions: [ '2013-12-02' ],
         serviceIdentifier: 'kinesis' },
      KinesisAnalytics: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2015-08-14': null },
         apiVersions: [ '2015-08-14' ],
         serviceIdentifier: 'kinesisanalytics' },
      KMS: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2014-11-01': null },
         apiVersions: [ '2014-11-01' ],
         serviceIdentifier: 'kms' },
      Lambda: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2014-11-11': null, '2015-03-31': null },
         apiVersions: [ '2014-11-11', '2015-03-31' ],
         serviceIdentifier: 'lambda' },
      Lightsail: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2016-11-28': null },
         apiVersions: [ '2016-11-28' ],
         serviceIdentifier: 'lightsail' },
      MachineLearning: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2014-12-12': null },
         apiVersions: [ '2014-12-12' ],
         serviceIdentifier: 'machinelearning' },
      MarketplaceCommerceAnalytics: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2015-07-01': null },
         apiVersions: [ '2015-07-01' ],
         serviceIdentifier: 'marketplacecommerceanalytics' },
      MarketplaceMetering: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2016-01-14': null },
         apiVersions: [ '2016-01-14' ],
         serviceIdentifier: 'marketplacemetering' },
      MobileAnalytics: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2014-06-05': null },
         apiVersions: [ '2014-06-05' ],
         serviceIdentifier: 'mobileanalytics' },
      OpsWorks: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2013-02-18': null },
         apiVersions: [ '2013-02-18' ],
         serviceIdentifier: 'opsworks' },
      OpsWorksCM: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2016-11-01': null },
         apiVersions: [ '2016-11-01' ],
         serviceIdentifier: 'opsworkscm' },
      Pinpoint: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2016-12-01': null },
         apiVersions: [ '2016-12-01' ],
         serviceIdentifier: 'pinpoint' },
      Polly: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2016-06-10': null },
         apiVersions: [ '2016-06-10' ],
         serviceIdentifier: 'polly',
         Presigner: { [Function: Signer] __super__: [Function: Object] } },
      RDS: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: 
          { '2013-01-10': null,
            '2013-02-12': null,
            '2013-09-09': null,
            '2014-09-01*': null,
            '2014-10-31': null },
         apiVersions: 
          [ '2013-01-10',
            '2013-02-12',
            '2013-09-09',
            '2014-09-01*',
            '2014-10-31' ],
         serviceIdentifier: 'rds' },
      Redshift: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2012-12-01': null },
         apiVersions: [ '2012-12-01' ],
         serviceIdentifier: 'redshift' },
      Rekognition: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2016-06-27': null },
         apiVersions: [ '2016-06-27' ],
         serviceIdentifier: 'rekognition' },
      Route53: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2013-04-01': null },
         apiVersions: [ '2013-04-01' ],
         serviceIdentifier: 'route53' },
      Route53Domains: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2014-05-15': null },
         apiVersions: [ '2014-05-15' ],
         serviceIdentifier: 'route53domains' },
      S3: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2006-03-01': null },
         apiVersions: [ '2006-03-01' ],
         serviceIdentifier: 's3',
         ManagedUpload: 
          { [Function: ManagedUpload]
            __super__: [Function: Object],
            addPromisesToClass: [Function: addPromisesToClass],
            deletePromisesFromClass: [Function: deletePromisesFromClass] } },
      ServiceCatalog: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2015-12-10': null },
         apiVersions: [ '2015-12-10' ],
         serviceIdentifier: 'servicecatalog' },
      SES: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2010-12-01': null },
         apiVersions: [ '2010-12-01' ],
         serviceIdentifier: 'ses' },
      Shield: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2016-06-02': null },
         apiVersions: [ '2016-06-02' ],
         serviceIdentifier: 'shield' },
      SimpleDB: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2009-04-15': null },
         apiVersions: [ '2009-04-15' ],
         serviceIdentifier: 'simpledb' },
      SMS: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2016-10-24': null },
         apiVersions: [ '2016-10-24' ],
         serviceIdentifier: 'sms' },
      Snowball: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2016-06-30': null },
         apiVersions: [ '2016-06-30' ],
         serviceIdentifier: 'snowball' },
      SNS: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2010-03-31': null },
         apiVersions: [ '2010-03-31' ],
         serviceIdentifier: 'sns' },
      SQS: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2012-11-05': null },
         apiVersions: [ '2012-11-05' ],
         serviceIdentifier: 'sqs' },
      SSM: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2014-11-06': null },
         apiVersions: [ '2014-11-06' ],
         serviceIdentifier: 'ssm' },
      StorageGateway: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2013-06-30': null },
         apiVersions: [ '2013-06-30' ],
         serviceIdentifier: 'storagegateway' },
      StepFunctions: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2016-11-23': null },
         apiVersions: [ '2016-11-23' ],
         serviceIdentifier: 'stepfunctions' },
      Support: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2013-04-15': null },
         apiVersions: [ '2013-04-15' ],
         serviceIdentifier: 'support' },
      SWF: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2012-01-25': null },
         apiVersions: [ '2012-01-25' ],
         serviceIdentifier: 'swf' },
      XRay: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2016-04-12': null },
         apiVersions: [ '2016-04-12' ],
         serviceIdentifier: 'xray' },
      WAF: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2015-08-24': null },
         apiVersions: [ '2015-08-24' ],
         serviceIdentifier: 'waf' },
      WAFRegional: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2016-11-28': null },
         apiVersions: [ '2016-11-28' ],
         serviceIdentifier: 'wafregional' },
      WorkSpaces: 
       { [Function]
         __super__: 
          { [Function: Service]
            __super__: [Function: Object],
            defineMethods: [Function: defineMethods],
            defineService: [Function: defineService],
            addVersions: [Function: addVersions],
            defineServiceApi: [Function: defineServiceApi],
            hasService: [Function],
            _serviceMap: [Object] },
         services: { '2015-04-08': null },
         apiVersions: [ '2015-04-08' ],
         serviceIdentifier: 'workspaces' } }