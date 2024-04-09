'use client';

import { useEffect, useState } from 'react';
import { hexToBytes, bytesToHex, randomBytes } from '@noble/hashes/utils';
import { Buffer } from 'buffer';

export default function FileVault() {
    const [vaultKey, setVaultKey] = useState<CryptoKey>();
    const [fileData, setFileData] = useState<string>();

    useEffect(() => {
        const deviceId = window.localStorage.getItem('deviceId');
        const deviceKeyData = window.localStorage.getItem('deviceKey');

        if (deviceId === null || deviceKeyData === null) {
            // We can't perform any crypto without the key
            fetch('/api/user/logout', {
                method: 'POST',
            }).then(() => {
                window.location.replace('/login');
            });
        } else {
            window.crypto.subtle
                .importKey(
                    'raw',
                    hexToBytes(deviceKeyData),
                    {
                        name: 'AES-KW',
                        length: 256,
                    },
                    true,
                    ['wrapKey', 'unwrapKey']
                )
                .then(async (deviceKey) => {
                    const res = await fetch(`/api/user/device/${deviceId}/key`);
                    const resJson = await res.json();
                    setVaultKey(
                        await window.crypto.subtle.unwrapKey(
                            'raw',
                            hexToBytes(resJson.key),
                            deviceKey,
                            'AES-KW',
                            'AES-GCM',
                            true,
                            ['encrypt', 'decrypt']
                        )
                    );
                });
        }
    }, []);

    return (
        <main className="flex justify-center">
            <div className="w-fit my-10">
                <div className="my-5">
                    <h3 className="text-xl font-medium my-5">Upload a file</h3>
                    <input
                        type="file"
                        onChange={async (e) => {
                            if (e.target.files?.length == 1) {
                                const file = e.target.files[0];
                                const fileObj = {
                                    name: file.name,
                                    type: file.type,
                                    data: Buffer.from(await file.arrayBuffer()).toString('base64'),
                                };

                                setFileData(JSON.stringify(fileObj));
                            }
                        }}
                    ></input>
                    <button
                        className="button bg-dark-purple mx-3 px-6 py-2 w-fit h-fit rounded-3xl text-white font-bold text-center"
                        onClick={async () => {
                            if (vaultKey !== undefined && fileData !== null) {
                                const enc = new TextEncoder();
                                const iv = randomBytes(16);
                                const fileCt = await window.crypto.subtle.encrypt(
                                    {
                                        name: 'AES-GCM',
                                        iv: iv,
                                    },
                                    vaultKey,
                                    enc.encode(fileData)
                                );

                                const res = await fetch('/api/vault/file', {
                                    method: 'POST',
                                    headers: {
                                        'Content-Type': 'application/json',
                                    },
                                    body: JSON.stringify({
                                        data: Buffer.from(fileCt).toString('base64'),
                                        iv: bytesToHex(iv),
                                    }),
                                });

                                if (res.status === 201) {
                                    alert('File upload successful');
                                } else {
                                    alert('Error: file upload was not successful');
                                }
                            }
                        }}
                    >
                        Submit
                    </button>
                </div>

                <div>
                    <h3 className="text-xl font-medium my-5">Download the file that you&apos;ve uploaded</h3>
                    <div className="flex justify-center">
                        <button
                            className="block button bg-dark-purple mx-3 px-6 py-2 w-fit h-fit rounded-3xl text-white font-bold text-center"
                            onClick={async () => {
                                if (vaultKey !== undefined) {
                                    const res = await fetch('/api/vault/file');

                                    if (res.status === 404) {
                                        alert('Error: you must upload a file first');
                                    } else if (res.status !== 200) {
                                        alert('Error: file download was not successful');
                                    } else {
                                        const resJson = await res.json();
                                        const iv = hexToBytes(resJson.iv);
                                        const fileCt = Buffer.from(resJson.data, 'base64');
                                        const dec = new TextDecoder();

                                        const fileObj = JSON.parse(
                                            dec.decode(
                                                await window.crypto.subtle.decrypt(
                                                    {
                                                        name: 'AES-GCM',
                                                        iv: iv,
                                                    },
                                                    vaultKey,
                                                    fileCt
                                                )
                                            )
                                        );

                                        const a = window.document.createElement('a');
                                        a.href = window.URL.createObjectURL(
                                            new Blob([Buffer.from(fileObj.data, 'base64')], { type: fileObj.type })
                                        );
                                        a.download = fileObj.name;

                                        document.body.appendChild(a);
                                        a.click();
                                        document.body.removeChild(a);
                                    }
                                }
                            }}
                        >
                            Download file
                        </button>
                    </div>
                </div>
            </div>
        </main>
    );
}
