import speakeasy from "speakeasy";

const secret = speakeasy.generateSecret({ length: 20 });
console.log("SUPERADMIN_2FA_KEY (base32):", secret.base32);