const { Keychain } = require("./password-manager");

async function test() {
    /*try {
        let keychain = await Keychain.init("mypassword");
        await keychain.set("google.com", "secure123");
        
        let pass = await keychain.get("google.com");
        console.log("Retrieved:", pass); // Should print "secure123"
    } catch (error) {
        console.error("Error:", error);
    }*/
        try {
            console.log("🔐 Initializing Keychain...");
            let keychain = await Keychain.init("mypassword");
    
            console.log("✅ Setting Passwords...");
            await keychain.set("google.com", "secure123");
            await keychain.set("facebook.com", "mypassword456");
    
            console.log("🔍 Retrieving Password...");
            let pass1 = await keychain.get("google.com");
            console.log("Google Password:", pass1); // Should print: secure123
    
            let pass2 = await keychain.get("facebook.com");
            console.log("Facebook Password:", pass2); // Should print: mypassword456
    
            console.log("💾 Dumping Keychain Data...");
            let dumped = await keychain.dump();
            console.log("Dumped Data:", dumped);
    
            console.log("📂 Loading Keychain from Dump...");
            let loadedKeychain = await Keychain.load("mypassword", dumped[0], dumped[1]);
    
            let loadedPass = await loadedKeychain.get("google.com");
            console.log("🔑 Loaded Google Password:", loadedPass); // Should match original
    
        } catch (error) {
            console.error("❌ Error:", error);
        }
}

test();
