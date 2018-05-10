var authorizationHeader = context.getVariable('request.header.Authorization');
var authorizationSections = authorizationHeader.split(' ')
var credential = authorizationSections[0];
var oauth_token = authorizationSections[1];
var signedHeaders =  authorizationSections[2];
var requestSignature = authorizationSections[3];
var apiKey = credential.split(':')[1]
var signature = requestSignature.split(':')[1]
var requestDateTime = context.getVariable('client.received.start.time');
var newDate = new Date(requestDateTime);
var formattedDate = newDate.getFullYear().toString() + "-" + formatNumber(newDate.getMonth()+1).toString() + "-" + formatNumber(newDate.getDate()).toString() + "T" + formatNumber(newDate.getHours()).toString() + ":" + formatNumber(newDate.getMinutes()).toString() + ":" + formatNumber(newDate.getSeconds()).toString() + ".000Z";
var token = oauth_token.split(':')[1]

context.setVariable("oauth_token", token)
context.setVariable("apiKey_variable", apiKey);
context.setVariable("signed_headers", signedHeaders.split(':')[1]);
context.setVariable("request_signature", signature);
context.setVariable("request_start_time", formattedDate)

function formatNumber(number){
    return ("0" + number).slice(-2);
}