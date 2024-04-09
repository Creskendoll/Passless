'use server';

import { User } from '../../../../../database/schemas';
import { NextResponse } from 'next/server';
import { argon2id } from '@noble/hashes/argon2';
import { argon2idParams } from '../params';
import { timingSafeEqual } from 'crypto';
import { createSession } from '../../../../session';
import { randomBytes } from 'crypto';

export async function POST(req: Request) {
    // Create session if username and passphrase hash is valid
    const data = await req.json();
    const user = await User.findOne({
        username: data.username,
    });
    const salt = user?.passphraseHashSalt || randomBytes(16);

    const hash = argon2id(data.passphraseHash, salt, argon2idParams);

    if (user === null || !timingSafeEqual(user.passphraseHash, Buffer.from(hash))) {
        return NextResponse.json(
            {},
            {
                status: 403,
            }
        );
    }

    await createSession(user._id);

    return NextResponse.json(
        {
            vaultKey: user.passphraseWrappedVaultKey,
            salt: user.passphraseKeySalt,
        },
        {
            status: 201,
        }
    );
}
