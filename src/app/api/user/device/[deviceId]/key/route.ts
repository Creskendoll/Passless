'use server';

import { IDevice } from '../../../../../../database/schemas';
import { NextResponse } from 'next/server';
import { getUserFromSession } from '../../../../../session';

export async function GET(_: Request, context: { params: { deviceId: string } }) {
    // Return deviceWrappedVaultKey if session and deviceId are valid
    const user = await getUserFromSession();
    const res = user?.devices.filter((device: IDevice) => device._id.equals(context.params.deviceId)) || [];

    if (res.length !== 1) {
        return NextResponse.json({}, { status: 404 });
    }

    return NextResponse.json({
        key: res[0].wrappedVaultKey,
    });
}
