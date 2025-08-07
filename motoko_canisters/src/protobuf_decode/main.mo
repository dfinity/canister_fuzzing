import Protobuf "mo:protobuf";
import Debug "mo:base/Debug";

/**
 * An actor that can parse raw Protobuf binary data.
 */
persistent actor ProtobufParser {

  /**
   * Parses the provided protobuf bytes.
   * This function does not return a result to the caller, but it will
   * print the outcome of the parsing attempt to the canister's logs.
   * @param bytes The raw protobuf data as an array of Nat8.
   */
  public func parse_protobuf(bytes: [Nat8]) : async () {

    // The function returns `async ()`, meaning the caller doesn't get a value back.
    // The actor attempts the parsing and handles the result internally.
    switch (Protobuf.fromRawBytes(bytes.vals())) {
      
      // Case 1: Parsing was successful
      case (#ok(rawFields)) {
        // Debug.print("✅ Successfully parsed protobuf data. Fields found:");
        
        // We can still process the raw fields, for example, by logging them.
        for (field in rawFields.vals()) {
          // Debug.print(
          //   "  - Field " # debug_show(field.fieldNumber) #
          //   " with wire type " # debug_show(field.wireType)
          // );
        };
      };

      // Case 2: An error occurred during parsing
      case (#err(error)) {
        // Log the error to the canister's output.
        // Debug.print("❌ Protobuf parsing error: " # error);
      };
    };
  };
}