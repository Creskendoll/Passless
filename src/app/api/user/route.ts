'use server';

import { readFileSync } from 'fs';
import { NextResponse } from 'next/server';
import { randomInt } from 'crypto';
import { User } from '../../../database/schemas';
import { createSession } from '../../session';

async function getAvailableUsername(wordlist: Array<string>): Promise<string> {
    while (true) {
        const username = [wordlist[randomInt(wordlist.length)], wordlist[randomInt(wordlist.length)]]
            .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
            .join('')
            .concat(randomInt(1000).toString());

        // Keep re-generating username until we find one that's available
        if ((await User.exists({ username: username })) === null) {
            return username;
        }
    }
}

export async function POST() {
    // Randomly assign an available username and save to a new session
    const wordlist = readFileSync('public/wordlist.txt', 'utf-8').split('\n');
    const username = await getAvailableUsername(wordlist);

    const newUser = new User({
        username: username,
        devices: [],
        sessionIds: [],
        authenticators: [],
        passphraseResetAllowed: true,
    });

    await newUser.save();
    await createSession(newUser._id);

    return NextResponse.json(
        {
            username: username,
        },
        {
            status: 201,
        }
    );
}
