var cacheSignature = context.getVariable("cache_signature");
var resultCacheValidation = validateCacheSignature(cacheSignature);
var requestDateFull = context.getVariable("request.header.Date");
var request_start = context.getVariable("request_start_time");
var timeToExpire = 10;

if (validateRequestDateTime(requestDateFull, request_start, timeToExpire) === false){
    context.setVariable("signature_validation_success", false);
    context.setVariable("description", "Token has expired.");
}
else{
    if (resultCacheValidation === false){
        context.setVariable("signature_validation_success", false);
        context.setVariable("description", "Token was use before.");
    }
    else
    {
        signMessage(requestDateFull, request_start);
    }
}

function validateRequestDateTime(requestDateFull, request_start, timeToExpire){
    var headerDate = dateStringToUTC(requestDateFull);
    var requestStart = new Date(request_start);
    
    diff = requestStart.getTime() - headerDate.getTime();
    var Seconds_from_T1_to_T2 = parseInt(Math.abs(diff / 1000));
    var result = false;
    print("\nheaderDate: " + headerDate);
    print("\nrequestDate: " + requestStart);
    print("\ndiff: " + Seconds_from_T1_to_T2);
    context.setVariable("time_diff", Seconds_from_T1_to_T2);
    if (Seconds_from_T1_to_T2 >= 0 && Seconds_from_T1_to_T2 < timeToExpire){
        result = true;
    }
    return result;
}

function validateCacheSignature(cacheValue){
    if (cacheValue && cacheValue.trim().length){
        return false;
    }
    else{
        return true;
    }
}

function signMessage(requestDateFull, request_start){
    var secretKey = context.getVariable("verifyapikey.verify-api-key.client_secret");
    var requestDate = requestDateFull.split('T')[0];
    var newLineCharacter = "\n";
    var serviceName = context.getVariable("apiproxy.name");
    var httpMethod = context.getVariable("message.verb");
    var completeUrl = context.getVariable("proxy.url");
    var payload = context.getVariable("request.content");
    var algorithm = "SHA256";
    var absolutePath = context.getVariable("request.path");
    var queryParameters = context.getVariable("request.querystring");
    
    var headers = context.getVariable("request.headers.names");
    headers = headers + '';
    headers = headers.slice(1, -1).split(', ');
    
    var canonicalRequest = finalCanonicalRequest(httpMethod, absolutePath, queryParameters, headers, payload, newLineCharacter);
    var hashCanonicalRequest = hashHex(canonicalRequest);
    var signedCanonicalRequest = signCanonicalRequest(hashCanonicalRequest, algorithm, requestDateFull, newLineCharacter);
    var signature = calculateSignature(secretKey, requestDate, serviceName, signedCanonicalRequest);
    
    print("\nAbsolute path: " + absolutePath);
    print("\nQuery parameters: " + queryParameters);
    print("\nCanonical request:\n" + canonicalRequest);
    print("\nHash canonical request: " + hashCanonicalRequest);
    print("\nSigned canonical request: " + signedCanonicalRequest);
    print("\nSigning key: " + signature[0])
    print("\nSignature: " + signature[1]);
    
    var request_signature = context.getVariable("request_signature");
    var result = false;
    var diff = 0;
    var description = "";
    print("\nRequest Signature: " + request_signature);
    print("\nApigee Signature: " + signature[1].toString());
    if (request_signature !== signature[1].toString()){
        description = "Request vs Apigee signature doesn't match."
    }
    else
    {
        result = true;
    }
    
    context.setVariable("description", description);
    context.setVariable("signature", signature[1]);
    context.setVariable("signature_validation_success", result);   
}

function calculateSignature(secret, date, serviceName, stringToSign){
    var firstKey = hmacValue("EAP1" + secret, date);
    var signingKey = hmacValue(firstKey, serviceName);
    var hashedSignature = hmacValue(signingKey, stringToSign);
    return [signingKey, hashedSignature];
  }

function signCanonicalRequest(hashedCanonicalRequest, algorithm, requestDate, newLineCharacter){
    var finalString = algorithm + newLineCharacter + requestDate + newLineCharacter + hashedCanonicalRequest
    return hashHex(finalString);
}

function finalCanonicalRequest(httpMethod, absolutePath, queryParameters, headers, payload, newLineCharacter){
    var signedHeaders = context.getVariable("signed_headers");
    var hashPayload = hashHex(payload);

    var stringHeaders = getHeadersToSign(headers, signedHeaders);
    var finalString = httpMethod + newLineCharacter + absolutePath + newLineCharacter + queryParameters + newLineCharacter + stringHeaders + signedHeaders + newLineCharacter + hashPayload;
    return finalString.toLowerCase();
}

function getHeadersToSign(headers, signedHeaders){
  var signedHeadersArray = [];
  signedHeadersArray = signedHeaders.split(";");
  var result = "";
  signedHeadersArray.forEach(function(h){
     var originalHeader = context.getVariable("request.header." + h);
     result = result + h + ":" + originalHeader + "\n";
  });
  return result;
}

function hmacValue(value, key){
    var hmac = CryptoJS.HmacSHA256(value, key);
    return hmac.toString();
}

function hashHex(value){
    var _sha256 = crypto.getSHA256();
    _sha256.update(value);
    return _sha256.digest();
}

function dateStringToUTC(dateString){
    var year = dateString.slice(0, 4);
    var month = dateString.slice(4, 6);
    var date = dateString.slice(6, 8);
    var hour = dateString.slice(9, 11);
    var minute = dateString.slice(11, 13);
    var seconds = dateString.slice(13, 15);
    var res = year + '-' + month + '-' + date + 'T' + hour + ":" + minute + ":" + seconds + ".000Z";
    return new Date(res);
}