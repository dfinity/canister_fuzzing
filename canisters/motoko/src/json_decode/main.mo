import Json "mo:json";

persistent actor JsonDecode {
    public func parse_json(bytes : Text) : async () {
    let _json_value = Json.parse(bytes);
  };
}