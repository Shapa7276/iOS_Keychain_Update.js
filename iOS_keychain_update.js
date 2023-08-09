/**
Frida script to update the keychain  on runtime

 * As per the Apple Documentation https://developer.apple.com/documentation/security/1393617-secitemupdate
 * SecItemUpdate Have two argument as  
 *  0)  _ query: CFDictionary,
    1)  _ attributesToUpdate: CFDictionary
 
 Second argument hold the value which getting updated in Keychain   
    
    Below  script to modifies  the second argument with "Test Data" or binary Asci[0x54, 0x65, 0x73, 0x74, 0x20, 0x44, 0x61, 0x74, 0x61] in Keychain (replace the data as per your need)
    
    
    frida -l iOS_Keychain_Update.js  'DVIA-v2'  -U
    
    Before directly using this script I recommend to use below script to monitor the format of data sent over to keychain 
   https://github.com/seemoo-lab/apple-continuity-tools/blob/565f2a95d8c3a958ffb430a5022a2df923eb5c1b/keychain_access/frida_scripts/hook_SecItemCopyMatching.js#L146
   
 */

var className = "Security";
var methodName = "SecItemUpdate"

var returnPtr = null;
Module.enumerateExports(className, {
    onMatch: function(fun) {

        if (fun.type == "function" && fun.name == methodName) {
            console.log("Found target method : " + methodName);

            try {
                Interceptor.attach(ptr(fun.address), {
                    onEnter: function(args) {

                        var params = ObjC.Object(args[1]); // CFDictionaryRef => NSDictionary
                        console.log("Query of  keychain items to update", ObjC.Object(args[0]))
                        // Convert the NSDictionary to an NSMutableDictionary to allow modification
                        params = ObjC.classes.NSMutableDictionary.dictionaryWithDictionary_(params);
                        var v = params.objectForKey_("v_Data");
                        var string = ObjC.classes.NSString.alloc();
                        v = string.initWithData_encoding_(v, 4).toString();
                        console.log("Original Value 'svce' v_Data:", v)
                        // Change the value for the key "v_Data" to "Test Data" ([0x54, 0x65, 0x73, 0x74, 0x20, 0x44, 0x61, 0x74, 0x61])
                        //To update with new value  change the value with number of bytes in memory allocation 
                        var newV = ObjC.classes.NSData.dataWithBytes_length_(Memory.alloc(9).writeByteArray([0x54, 0x65, 0x73, 0x74, 0x20, 0x44, 0x61, 0x74, 0x61]), 9);

                        // Set the updated value in the NSMutableDictionary

                        params.setObject_forKey_(newV, "v_Data");
                        var string = ObjC.classes.NSString.alloc();
                        var newvalue = string.initWithData_encoding_(newV, 4).toString();
                        console.log("Updated the above 'svce' v_Data:", newvalue);

                        // Assign the updated dictionary back to the original argument
                        args[1] = params;

                    },
                    onLeave: function() {

                    },
                });
            } catch (error) {
                console.log("Ignoring " + fun.name + ": " + error.message);
            }
        }

    },
    onComplete: function(e) {


    }
});
