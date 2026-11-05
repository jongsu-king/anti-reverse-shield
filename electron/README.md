# electron — JavaScript app hardening

Electron is the weakest target: unpacking `app.asar` yields full source.
Apply these **in order**:

1. **Obfuscate** sensitive JS — `npm run obfuscate` (`build/obfuscate.config.js`)
2. **Compile to V8 bytecode** — `npm run bytecode` (`build/build-bytecode.js`), removes plaintext `.js`
3. **Flip Electron fuses** after packaging — `build/fuses.js`
   - `RunAsNode: false` and `EnableNodeCliInspectArguments: false` are the critical ones.
     Without them an attacker launches your app as plain node and dumps everything.
4. **DevTools guard** in the renderer — `src/devtools-guard.js`

> None of this is unbreakable. bytenode raises cost a lot but can be disassembled.
> Keep licensing/payment/secret logic on the server.
