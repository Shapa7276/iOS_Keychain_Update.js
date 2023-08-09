# iOS_Keychain_Update

Frida script to update the keychain  on runtime

 * As per the Apple Documentation https://developer.apple.com/documentation/security/1393617-secitemupdate
 * SecItemUpdate Have two argument as  
 *  0)  _ query: CFDictionary,
    1)  _ attributesToUpdate: CFDictionary
 
 Second argument hold the value which getting updated in Keychain   
    
Below  script to modifies  the second argument with "Test Data" or binary Asci[0x54, 0x65, 0x73, 0x74, 0x20, 0x44, 0x61, 0x74, 0x61] in Keychain (replace the data as per your need)

![image](https://github.com/Shapa7276/iOS_Keychain_Update.js/assets/41251016/1b6e21b5-a02d-44c7-9837-3c3880fb108c)

```frida -l iOS_Keychain_Update.js  'DVIA-v2'  -U```

![image](https://github.com/Shapa7276/iOS_Keychain_Update.js/assets/41251016/acb35203-fc4c-498e-af65-8ee5d6fdcdce)

