import init, { chiffre, crypt_aes_gcm_siv, decrypt_aes_gcm_siv } from "./pkg/chris_math.js";

async function hash(mdp) {
    await init();
    console.log(chiffre(mdp));
}

async function chiffre_dechiffre(messageAChiffrer) {
    await init()
    let messageChiffre = await crypt_aes_gcm_siv(messageAChiffrer, "password");
    console.log(messageChiffre);
    let messageDechiffre = await decrypt_aes_gcm_siv(messageChiffre);
    console.log(messageDechiffre);
}


let mdpDiv = document.getElementById("mdp");


mdpDiv.addEventListener("change", function (event) {
    let mdp = mdpDiv.value;
    console.log(mdp);
    hash(mdp);
})

let messageDiv = document.getElementById("message");

messageDiv.addEventListener("change", function (event) {
    let message = messageDiv.value;
    console.log(message);
    chiffre_dechiffre(message);
})
