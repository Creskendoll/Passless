'use server';

import Link from 'next/link';
import Image from 'next/image';
import { cookies } from 'next/headers';
import { Session } from '@/database/schemas';
import { LogoutButton } from './logoutButton';
import { getUserFromSession } from './session';

export async function Header() {
    const user = await getUserFromSession();

    return (
        <div className="flex justify-between">
            <Link href="/">
                <Image src="/logo.jpg" width={198} height={88} alt="Passless"></Image>
            </Link>
            {user !== null && user.passphraseHash !== undefined && (
                <div className="grid content-center">
                    <LogoutButton />
                </div>
            )}
        </div>
    );
}
