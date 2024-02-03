"use client";

import { useCallback, useEffect, useState } from "react";
import { bytesToHex } from "@noble/hashes/utils";
import { rand } from "../utils";
import { pbkdf2 } from "@noble/hashes/pbkdf2";
import { pbkdf2Params } from "../params";
import { sha256 } from "@noble/hashes/sha256";
import { randomBytes } from "@noble/hashes/utils";

// TODO:
// - make this into a server component
// - redirect to vault if user is already signed in
// - in the future, it will be necessary to allow user to reset passphrase
export default function RegisterForm() {
    const [username, setUsername] = useState<string>("");
    const [wordList, setWordList] = useState<string[]>([]);
    const [passphrase, setPassphrase] = useState<string[]>();
    const [passphraseKeyData, setPassphraseKeyData] = useState<Uint8Array>();
    const [passphraseKeySalt, setPassphraseKeySalt] = useState<Uint8Array>();
    const [passphraseHash, setPassphraseHash] = useState<Uint8Array>();
    const [loading, setLoading] = useState<boolean>(true);

    const genRandPassphrase = (words: string[]) => {
        return new Array(6)
            .fill("")
            .map(() => words[Math.floor(rand() * words.length)]);
    };

    const populateWordList = useCallback(async (): Promise<string[]> => {
        // Get word list
        const wordText = await (await fetch("/wordlist.txt")).text();
        const words = wordText.split("\n");
        if (!words.length) return [];
        setWordList(words);

        return words;
    }, [setWordList]);

    const populateCredentials = useCallback(
        async (words: string[]): Promise<string[]> => {
            // Generate passphrase and username after wordlist loads
            const phrase = genRandPassphrase(words);
            setPassphrase(phrase);

            // Fetch valid username
            const rJson = await (
                await fetch("/api/user", {
                    method: "POST",
                })
            ).json();
            setUsername(rJson.username);
            return [rJson.username, ...phrase];
        },
        [setUsername, setPassphrase]
    );

    const populatePassphraseMeta = useCallback(
        ([user, ...phrase]: string[]) => {
            // Generate keys
            // Prevent user interaction until key generation is complete
            setLoading(true);

            const passString = phrase.join("-");
            const keySalt = randomBytes(16);
            setPassphraseKeySalt(keySalt);

            setPassphraseKeyData(
                pbkdf2(sha256, passString, keySalt, pbkdf2Params)
            );

            // Salting the passphrase hash with username
            // will allow us to calculate the passphrase hash
            // without the need to expose the salt via an API endpoint
            setPassphraseHash(pbkdf2(sha256, passString, user, pbkdf2Params));

            setLoading(false);
        },
        [
            setLoading,
            setPassphraseKeySalt,
            setPassphraseKeyData,
            setPassphraseHash,
        ]
    );

    useEffect(() => {
        populateWordList()
            .then(populateCredentials)
            .then(populatePassphraseMeta);
    }, [populateCredentials, populateWordList, populatePassphraseMeta]);

    return (
        <main className="flex justify-center">
            <div className="w-xl my-10">
                <h2 className="text-3xl font-bold mb-5">
                    Generate Username and Passphrase
                </h2>
                <p>
                    You will need your username and passphrase to access your
                    account. Please write them down and don&apos;t lose them.
                </p>

                <h3 className="text-xl font-medium my-5">Username</h3>
                <input
                    disabled
                    type="text"
                    className="block bg-light-purple m-3 px-6 py-2 w-80 rounded-3xl"
                    value={username}
                ></input>
                <div className="flex justify-center">
                    <button
                        className={
                            loading
                                ? "inline font-bold cursor-wait"
                                : "inline font-bold cursor-pointer hover:underline"
                        }
                        onClick={() => {
                            if (!loading) {
                                fetch("/api/user", {
                                    method: "POST",
                                })
                                    .then((r) => r.json())
                                    .then((rJson) => {
                                        setUsername(rJson.username);
                                    });
                            }
                        }}
                    >
                        <img
                            className="inline w-8 h-8 my-5"
                            src="/reset.svg"
                        ></img>
                        Regenerate username
                    </button>
                </div>

                <h3 className="text-xl font-medium mb-5">Passphrase</h3>
                <div className="grid grid-cols-3 gap-4 m-5 my-10 w-full">
                    {passphrase?.map((w, i) => {
                        return (
                            <div
                                key={i}
                                className="bg-light-purple w-30 h-12 px-4 py-3 rounded-md text-center font-bold"
                            >
                                {w}
                            </div>
                        );
                    })}
                </div>
                <div className="flex justify-center">
                    <button
                        className={
                            loading
                                ? "font-bold cursor-wait"
                                : "font-bold cursor-pointer hover:underline"
                        }
                        onClick={() => {
                            if (!loading) {
                                setPassphrase(genRandPassphrase(wordList));
                            }
                        }}
                    >
                        <img
                            className="inline w-8 h-8 my-5"
                            src="/reset.svg"
                        ></img>
                        Regenerate passphrase
                    </button>
                </div>
                <div className="flex justify-center">
                    <button
                        className={
                            loading
                                ? "block button bg-dark-purple m-3 px-6 py-2 w-96 rounded-3xl text-white font-bold cursor-wait"
                                : "block button bg-dark-purple m-3 px-6 py-2 w-96 rounded-3xl text-white font-bold cursor-pointer"
                        }
                        onClick={async () => {
                            if (
                                !loading &&
                                passphraseKeyData !== undefined &&
                                passphraseKeySalt !== undefined &&
                                passphraseHash !== undefined
                            ) {
                                setLoading(true);

                                const vaultKey =
                                    await window.crypto.subtle.generateKey(
                                        {
                                            name: "AES-GCM",
                                            length: 256,
                                        },
                                        true,
                                        ["encrypt", "decrypt"]
                                    );

                                const passphraseKey =
                                    await window.crypto.subtle.importKey(
                                        "raw",
                                        passphraseKeyData,
                                        {
                                            name: "AES-KW",
                                            length: 256,
                                        },
                                        true,
                                        ["wrapKey", "unwrapKey"]
                                    );

                                // Wrap vault key with passphrase derived key
                                // Send wrapped vault key and passphrase hash to the server
                                const passWrappedVaultKey = new Uint8Array(
                                    await window.crypto.subtle.wrapKey(
                                        "raw",
                                        vaultKey,
                                        passphraseKey,
                                        "AES-KW"
                                    )
                                );

                                fetch("/api/user/passphrase", {
                                    method: "POST",
                                    headers: {
                                        "Content-Type": "application/json",
                                    },
                                    body: JSON.stringify({
                                        passphraseWrappedVaultKey:
                                            bytesToHex(passWrappedVaultKey),
                                        passphraseKeySalt:
                                            bytesToHex(passphraseKeySalt),
                                        passphraseHash:
                                            bytesToHex(passphraseHash),
                                    }),
                                }).then((res) => {
                                    setLoading(false);

                                    if (res.status === 201) {
                                        window.location.replace("/login");
                                    } else {
                                        // TODO
                                    }
                                });
                            }
                        }}
                    >
                        I saved my username and passphrase
                    </button>
                </div>
            </div>
        </main>
    );
}
