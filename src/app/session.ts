import { randomBytes } from 'crypto';
import { Session, User, IUser } from '../database/schemas';
import { cookies } from 'next/headers';
import { Types } from 'mongoose';

export async function createSession(userId: Types.ObjectId): Promise<string> {
    // Create session, update user, and set cookie
    // Return session ID
    const user = await User.findById(userId);
    // TODO: could it be better to use UUID?
    const sessionId = randomBytes(32).toString('base64');
    await Session.replaceOne(
        {},
        {
            user: user._id,
            sid: sessionId,
        },
        {
            upsert: true,
        }
    );

    user.sessionIds.push(sessionId);
    await user.save();

    cookies().set({
        name: 'sid',
        value: sessionId,
        httpOnly: true,
        path: '/',
        sameSite: 'strict',
    });

    return sessionId;
}

export async function destroySessionBySID(sid: string) {
    const session = await Session.findOne({ sid: sid });
    const user = await User.findById(session.user);

    if (session === null || user === null) {
        return;
    }

    user.sessionIds = user.sessionIds.filter((s: string) => s !== sid);

    await user.save();
    await Session.findByIdAndDelete(session._id);
}

export async function destroySession() {
    const sid = cookies().get('sid')?.value;
    await destroySessionBySID(sid || '');
    cookies().delete('sid');
}

export async function getUserBySID(sid: string): Promise<IUser | null> {
    const session = await Session.findOne({ sid: sid });
    return await User.findById(session?.user);
}

export async function getUserFromSession(): Promise<IUser | null> {
    const sid = cookies().get('sid')?.value;
    return await getUserBySID(sid || '');
}
