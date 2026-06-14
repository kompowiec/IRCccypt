IRCrypt – Encryption Layer for IRC
==================================
IRC is pretty good protocol, especially if you have normie friendly client, like IRCcloud, The longue (my fav), or convos.chat. But main issue here is lack of E2E.

The current state of affairs is classic fragmentation: standards like FiSH, OTR (Off-the-Record), work, but usually only when both parties use the same client.

The second option is ZNC, but it still only works when both parties use ZNC. However, it's a step up because it's independent of the IRC client.

The third option is DCC SCHAT (Direct Client-to-Client Synchronous Chat) which you can DM using encryption from TLS but bypasses the server so it fails due to the lack of a public IP (NAT/CGNAT problems with modern internet providers). So we need fallback to IRC.

So, how can you ensure that the interlocutor can decipher the message without forcing him to install dedicated clients or bouncers?

Imagine a courier (IRC server) carries a letter. If the letter is written in a universal cipher (e.g., Caesar Cipher or Enigma), the courier can read it but won't understand it. The recipient uses a handy codebook to decipher it. The letter appears as a regular letter (ASCII text), so it passes through standard mail channels.

Since we can't force the other party to use the same client, we need to separate the decryption layer from the IRC client. The other party needs a decryption tool that they can run on anything.

My take is to treat cryptography as a regular Unix pipe (|). Your interlocutor does not change the IRC client, but uses the universal POSIX standard.

Sending: You type a message in your client, and your local proxy/plugin converts it to: [E2EE] U2FsdGVkX19...

Receiving at the recipient: The recipient copies the encrypted text from any IRC client and pastes it into the terminal:
```bash
echo "U2FsdGVkX19..." | openssl enc -aes-256-cbc -d -a -k "shared_sekret"
```
The OpenSSL tool is preinstalled on 99% of Linux/BSD/macOS systems. No vendor lock-in, no additional software, and full security. OpenSSL is based on standards that cannot "break down" when the IRC client is updated. You can implement OpenSSL command in 5 minutes by writing a simple alias in your current IRC client. All you need is integration for your IRC client, bypassing the only drawback of the STDIN/STDOUT pipeline, which is the need to constantly copy text to the terminal.

Workflow
---------
Let's say you want to chat securely with user Alice. You both need to load this plugin into your IRC clients (in this case, HexChat and WeeChat).

Initialization (You): In the chat window with Alice, enter:

/crypto_init

The plugin will spit out a string in the window, e.g.: DH_KEY:MC4CAQAwBQYDK2VuBCIE...

Exchange (You): Copy this string and send it to Alice in a regular IRC message.

Initialization (Alice): Alice also enters /crypto_init on his own and sends you his key DH_KEY:MIGbMBAGByqGSM49AgEG...

Key Mixing (Both): * You copy Alice key and enter: /crypto_derive DH_KEY:MIGbMBAG...

Alice copies your key and enters: /crypto_derive DH_KEY:MC4CAQAw...

Done! From now on, every line you type in the chat window will automatically be changed to the server-indecipherable string [E2EE]:U2FsdGVkX19.... When Alice receives it, his plugin will automatically decrypt the text on the fly and display it with a lock icon 🔒.

Ephemeral Security: Session private keys are stored in /tmp (which is mounted in RAM as tmpfs in most Linux distributions). After restarting your computer or disabling the WeeChat/HexChat, old conversations cannot be decrypted, even if someone later obtains your shared secret key (Perfect Forward Secrecy).

Demo: https://www.youtube.com/watch?v=v1mXAOH4po8
