import Blob "mo:base/Blob";

persistent actor CandidParser {

  public type HeaderField = (Text, Text);
  public type HttpRequest = {
    url : Text;
    method : Text;
    body : Blob;
    headers : [HeaderField];
    certificate_version : ?Nat16;
  };
  public type HttpResponse = {
    body : Blob;
    headers : [HeaderField];
    upgrade : ?Bool;
    streaming_strategy : ?StreamingStrategy;
    status_code : Nat16;
  };
  public type HttpUpdateRequest = {
    url : Text;
    method : Text;
    body : Blob;
    headers : [HeaderField];
  };
  public type StreamingCallbackHttpResponse = {
    token : ?StreamingToken;
    body : Blob;
  };
  public type StreamingStrategy = {
    #Callback : {
      token : StreamingToken;
      callback : shared query StreamingToken -> async ?StreamingCallbackHttpResponse;
    };
  };
  public type StreamingToken = {};

  public func parse_candid(bytes : Blob) : async () {
    let response : ?HttpResponse = from_candid (bytes);
  };

};
