'use server';

import { NextResponse } from 'next/server';
import { destroySession } from '../../../session';

export async function POST() {
    await destroySession();
    return NextResponse.json({});
}
