import { UltraHonkBackend } from '@aztec/bb.js';
import { Noir } from '@noir-lang/noir_js';
import worm from "../target/worm.json"
import inp from "./inp.json"

const show = (id, content) => {
    const container = document.getElementById(id);
    container.appendChild(document.createTextNode(content));
    container.appendChild(document.createElement("br"));
};

document.getElementById("submit").addEventListener("click", async () => {
    try {
        const noir = new Noir(worm);
        const backend = new UltraHonkBackend(worm.bytecode);
        show("logs", "Generating witness... ⏳");
        const { witness } = await noir.execute(inp);
        show("logs", "Generated witness... ✅");
        show("logs", "Generating proof... ⏳");
        const proof = await backend.generateProof(witness);
        show("logs", "Generated proof... ✅");
        show("results", proof.proof);
        show('logs', 'Verifying proof... ⌛');
        const isValid = await backend.verifyProof(proof);
        show("logs", `Proof is ${isValid ? "valid" : "invalid"}... ✅`);

    } catch (e) {
        show("logs", "Oh 💔" + e);
    }
});