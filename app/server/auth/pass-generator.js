const prompts = require('prompts');
const bcrypt = require("bcryptjs");
const fs = require("fs");

async function main() { 
  const userResponse = await prompts({
      type: 'text',
      name: 'password',
      message: 'Enter new password:'
  });

  const userPasswordHash = bcrypt.hashSync(userResponse.password, 10);
  
  fs.writeFile("password.txt", userPasswordHash, (err) => {
    if (err) console.log(err);
  });
};

main();
