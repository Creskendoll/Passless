'use server';

import { getUserFromSession } from '../../../session';
import { NextResponse } from 'next/server';
import { File, User } from '../../../../database/schemas';

export async function GET() {
    // Retrieve file
    const user = await getUserFromSession();

    if (user === null) {
        return NextResponse.json(
            {},
            {
                status: 403,
            }
        );
    }

    if (user.file === undefined) {
        return NextResponse.json(
            {},
            {
                status: 404,
            }
        );
    }

    return NextResponse.json({
        data: user.file.data,
        iv: user.file.iv,
    });
}

export async function POST(req: Request) {
    // Save file
    const reqJson = await req.json();
    const user = await getUserFromSession();

    if (user === null) {
        return NextResponse.json(
            {},
            {
                status: 403,
            }
        );
    }

    const newFile = new File({
        data: reqJson.data,
        iv: reqJson.iv,
    });

    await newFile.save();
    await User.findByIdAndUpdate(user._id, {
        file: newFile,
    });

    return NextResponse.json(
        {},
        {
            status: 201,
        }
    );
}
