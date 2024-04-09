'use client';

import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import { pbkdf2 } from '@noble/hashes/pbkdf2';
import { pbkdf2Params } from '../params';
import { sha256 } from '@noble/hashes/sha256';
import { FormEvent, useState } from 'react';

export default function LoginForm() {
    const [username, setUsername] = useState<string>('');
    const [passphrase, setPassphrase] = useState<string[]>(new Array(6).fill(''));
    const [loading, setLoading] = useState<boolean>(false);
    const [error, setError] = useState<string>('');
    const [selectedWord, setSelectedWord] = useState<number>(-1);

    const login = async (username: string, passphrase: string): Promise<CryptoKey | null> => {
        // Return unwrapped vault key if authentication is successful and null otherwise
        const hash = pbkdf2(sha256, passphrase, username, pbkdf2Params);

        const authRes = await fetch('/api/user/passphrase/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                username: username,
                passphraseHash: bytesToHex(hash),
            }),
        });

        if (authRes.status === 201) {
            // Unwrap and return vault key
            const authResJson = await authRes.json();

            const passphraseKeyData = pbkdf2(sha256, passphrase, hexToBytes(authResJson.salt), pbkdf2Params);

            const passphraseKey = await window.crypto.subtle.importKey(
                'raw',
                passphraseKeyData,
                {
                    name: 'AES-KW',
                    length: 256,
                },
                true,
                ['wrapKey', 'unwrapKey']
            );

            return await window.crypto.subtle.unwrapKey(
                'raw',
                hexToBytes(authResJson.vaultKey),
                passphraseKey,
                'AES-KW',
                'AES-GCM',
                true,
                ['encrypt', 'decrypt']
            );
        }

        return null;
    };

    return (
        <main className="flex justify-center">
            <div className="w-xl my-10">
                <h2 className="text-3xl font-bold mb-5">Validate Username and Passphrase</h2>
                <p>Please validate your username and passphrase before proceeding.</p>

                <h3 className="text-xl font-medium my-5">Enter Username</h3>
                <input
                    autoFocus
                    type="text"
                    className="block bg-light-purple m-3 px-6 py-2 w-80 rounded-3xl"
                    placeholder="Enter username"
                    onChange={(e) => {
                        setUsername(e.target.value);
                    }}
                ></input>

                <h3 className="text-xl font-medium mb-5">Enter Passphrase</h3>
                <div
                    className="grid grid-cols-3 gap-4 m-5 my-5"
                    onBlur={() => {
                        setSelectedWord(-1);
                    }}
                >
                    {passphrase.map((_, i) => {
                        return (
                            <div
                                key={i}
                                className="bg-light-purple w-30 h-12 px-4 py-3 rounded-md text-center font-bold cursor-text"
                                onClick={() => {
                                    document.getElementById(`passphraseWord${i}`)?.focus();
                                }}
                            >
                                <input
                                    type={selectedWord === i ? 'text' : 'password'}
                                    onFocus={() => {
                                        setSelectedWord(i);
                                    }}
                                    id={`passphraseWord${i}`}
                                    className="max-w-full bg-transparent outline-none focus:border-b-2 border-medium-purple"
                                    placeholder={'Enter word ' + (i + 1)}
                                    onInput={(e: FormEvent<HTMLInputElement>) => {
                                        setPassphrase((pass) => {
                                            pass[i] = (e.target as HTMLInputElement).value.toLowerCase();
                                            return pass;
                                        });
                                    }}
                                ></input>
                            </div>
                        );
                    })}
                </div>
                <div className="flex justify-center">
                    <button
                        className={
                            loading
                                ? 'block button bg-dark-purple m-3 px-6 py-2 w-80 rounded-3xl text-white font-bold cursor-wait'
                                : 'block button bg-dark-purple m-3 px-6 py-2 w-80 rounded-3xl text-white font-bold cursor-pointer'
                        }
                        onClick={async () => {
                            if (username === '') {
                                setError('Please enter your username');
                            } else if (passphrase.some((w) => w === '')) {
                                setError('Please completely fill in your passphrase');
                            } else {
                                setLoading(true);
                                const vaultKey = await login(username, passphrase.join('-'));

                                if (vaultKey !== null) {
                                    // Generate new device key
                                    // Save device key to server and local storage
                                    const deviceKey = await window.crypto.subtle.generateKey(
                                        {
                                            name: 'AES-KW',
                                            length: 256,
                                        },
                                        true,
                                        ['wrapKey', 'unwrapKey']
                                    );

                                    const deviceKeyData = new Uint8Array(
                                        await window.crypto.subtle.exportKey('raw', deviceKey)
                                    );

                                    const wrappedVaultKey = new Uint8Array(
                                        await window.crypto.subtle.wrapKey('raw', vaultKey, deviceKey, 'AES-KW')
                                    );

                                    const res = await fetch('/api/user/device', {
                                        method: 'POST',
                                        headers: {
                                            'Content-Type': 'application/json',
                                        },
                                        body: JSON.stringify({
                                            wrappedVaultKey: bytesToHex(wrappedVaultKey),
                                        }),
                                    });

                                    const resJson = await res.json();

                                    window.localStorage.setItem('deviceId', resJson.deviceId);
                                    window.localStorage.setItem('deviceKey', bytesToHex(deviceKeyData));

                                    window.location.replace('/vault');
                                } else {
                                    setError('Username or passphrase is not correct');
                                }

                                setLoading(false);
                            }
                        }}
                    >
                        Continue
                    </button>
                </div>
                <div className="flex justify-center">
                    <p className="text-red-500">{error}</p>
                </div>
            </div>
        </main>
    );
}
