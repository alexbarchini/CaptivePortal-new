#!/usr/bin/env node
const argon2 = require('argon2');

async function main() {
  const password = process.argv[2];
  if (!password) {
    console.error('Uso: node scripts/generate-admin-password-hash.js "<senha_admin>"');
    process.exit(1);
  }
  const hash = await argon2.hash(password);
  console.log(hash);
}

main().catch((error) => {
  console.error('Falha ao gerar hash:', error.message);
  process.exit(1);
});
