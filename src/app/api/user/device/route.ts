'use server';

import { Device, User } from '../../../../database/schemas';
import { NextResponse } from 'next/server';
import { getUserFromSession } from '../../../session';

export async function POST(req: Request) {
    // Create a new device and attach to user
    const data = await req.json();
    const user = await getUserFromSession();

    if (user === null) {
        return NextResponse.json(
            {},
            {
                status: 403,
            }
        );
    }

    const newDevice = new Device({ wrappedVaultKey: data.wrappedVaultKey });
    await newDevice.save();

    const userModel = await User.findById(user._id);
    userModel.devices.push(newDevice);
    await userModel.save();

    return NextResponse.json(
        {
            // TODO: could it be better to use UUID?
            deviceId: newDevice._id,
        },
        {
            status: 201,
        }
    );
}
