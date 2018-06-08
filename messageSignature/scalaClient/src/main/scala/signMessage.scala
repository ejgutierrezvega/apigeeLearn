import scala.collection.immutable.{HashMap, ListMap}
import com.roundeights.hasher.Implicits._
import io.lemonlabs.uri.Url
import java.text.SimpleDateFormat
import java.util.{Calendar, TimeZone}

import scalaj.http._
import scala.util.parsing.json._

object signMessage extends App {
  println("Starting")

  //Get access token
  /*
  val tokenUrl = "https://egutierrez-eval-test.apigee.net/oauth/accesstoken"
  val base64ClientSecret = "d2dqN29WRlNQNm40QUZwN2JUcmczRVNDWVJVdkFOM0Q6R0RCM0JNelZTTUxiZkk2Rw=="
  val resultToken : HttpResponse[String] = Http(tokenUrl)
    .header("Content-Type", "application/x-www-form-urlencoded")
    .header("Authorization", s"Basic ${base64ClientSecret}")
    .option(HttpOptions.readTimeout(10000))
    .postForm(Seq("username" -> "apininja", "password" -> "iloveapis", "grant_type" -> "password"))
    .asString


  val jsonToken = JSON.parseFull(resultToken.body).get
  val token = jsonToken.asInstanceOf[HashMap[String, String]].get("access_token").get
  println("\nResponse Token status: " + resultToken.code)
  println("\nResponse Token: " + token)
*/

  val token = ""
  val today = Calendar.getInstance.getTime
  var formatUTC = new SimpleDateFormat("yyyyMMdd'T'HHmmss'Z'")
  var formatDateUTC = new SimpleDateFormat("yyyyMMdd")
  formatUTC.setTimeZone(TimeZone.getTimeZone("UTC"));
  formatDateUTC.setTimeZone(TimeZone.getTimeZone("UTC"));

  val clientId : String = "rp7iUCJopsoADM7X6yzQm3eNNvoJ8lGe"
  val secretKey : String = "7yUbYTcc0c1IcwGW"
  val requestDate : String = formatDateUTC.format(today)
  val requestDateFull : String = formatUTC.format(today)
  val newLineCharacter : String = "\n"
  val serviceName : String = "products-signature"
  val httpMethod : String = "GET"
  val completeUrl: String = "https://devapi.esurance.com/products-signature/products"
  val headers  = Map("Content-Type" -> "application/json",
    "host" -> "esurance-preprod-dev.apigee.net",
    "date" -> requestDateFull,
    "Bearer" -> token
  )
  val payload : String = ""
  val algorithm : String = "SHA256"

  val absolutePath = getAbsolutePath(completeUrl)
  val queryParameters = getQueryParameters(completeUrl)

  val sortedHeaders : ListMap[String, String]= sortHeaders(headers)
  val signedHeaders : String = signHeaders(sortedHeaders)

  val canonicalRequest = finalCanonicalRequest(httpMethod, absolutePath, queryParameters, sortedHeaders, signedHeaders, payload)
  val hashCanonicalRequest = hash(canonicalRequest)
  val signedCanonicalRequest = signCanonicalRequest(hashCanonicalRequest, algorithm, requestDateFull)
  val signature = calculateSignature(secretKey, requestDate, serviceName, signedCanonicalRequest)

  println("\nRequest date: " + requestDate)
  println("\nRequest date full: " + requestDateFull)
  println("\nAbsolute path: " + absolutePath)
  println("\nQuery parameters: " + queryParameters)
  println("\nCanonical request: \n" + canonicalRequest)
  println("\nHash canonical request: " + hashCanonicalRequest)
  println("\nSigned canonical request: " + signedCanonicalRequest)
  println("\nSigning key: " + signature._1)
  println("\nSignature: " + signature._2)
  println("\nRequest Date: " + requestDateFull)

  val authorizationHeader = s"credential:$clientId bearer:$token signedHeaders:$signedHeaders Signature:${signature._2}"

  val result : HttpResponse[String] = Http(completeUrl)
    .header("Content-Type", "application/json")
    .header("Accept", "application/json")
    .header("Date", formatUTC.format(today))
    .header("Authorization", authorizationHeader)
    .header("Bearer", token)
    .option(HttpOptions.readTimeout(10000)).asString

  println("\nResponse status: " + result.code)
  println("\nResponse body: " + result.body)


  Thread.sleep(10000) // wait for 1000 millisecond

  val result2 : HttpResponse[String] = Http(completeUrl)
    .header("Content-Type", "application/json")
    .header("Accept", "application/json")
    .header("Date", formatUTC.format(today))
    .header("Authorization", authorizationHeader)
    .header("Bearer", token)
    .option(HttpOptions.readTimeout(10000)).asString

  println("\nResponse status: " + result2.code)
  println("\nResponse body: " + result2.body)

  Thread.sleep(1000) // wait for 1000 millisecond

  def calculateSignature(secret: String, date: String, serviceName : String, stringToSign: String) : (String, String) = {
    val firstKey = hmac("EAP1" + secret, date)
    println("Sign A: " + firstKey)
    val signingKey = hmac(firstKey, serviceName)

    val hashedSignature = hmac(signingKey, stringToSign)
    (signingKey, hashedSignature)
  }

  def signCanonicalRequest(hashedCanonicalRequest: String, algorithm: String, requestDate: String) : String={
    val finalString : String = algorithm + newLineCharacter + requestDate + newLineCharacter + hashedCanonicalRequest
    hash(finalString)
  }

  def finalCanonicalRequest(httpMethod: String, absolutePath: String, queryParameters : String, sortedHeaders : Map[String, String], signedHeaders : String, payload : String) : String ={
    val hashPayload = hash(payload)
    val stringHeaders = sortedHeaders.map{
      case (k,v) => k + ":" + v
    }.mkString(newLineCharacter).toLowerCase

    val finalString : String = httpMethod + newLineCharacter + absolutePath + newLineCharacter + queryParameters + newLineCharacter + stringHeaders + newLineCharacter + signedHeaders + newLineCharacter + hashPayload
    finalString.toLowerCase
  }

  def hash(valueToHash : String): String ={
    valueToHash.sha256.hex
  }

  def hmac(valueToHash: String, key:String) : String ={
    val result = valueToHash.hmac(key).sha256.hex
    result
  }

  def sortHeaders(headers : Map[String, String]) : ListMap[String, String] ={
    ListMap(headers.toSeq.sortBy(_._1):_*)
  }

  def signHeaders(headers : ListMap[String, String]) : String = {
    headers.map{
      case (k,v) => k
    }.mkString(";").toLowerCase
  }

  def getAbsolutePath(uriInput : String) : String ={
    Url.parse(uriInput).path.toString()
  }

  def getQueryParameters(uriInput: String) : String ={
    Url.parse(uriInput).query.toString().replace("?", "")
  }

  def string2hex(str: String): String = {
    str.toList.map(_.toInt.toHexString).mkString
  }

  println("Finished")
}
