'use server';

import { redirect } from 'next/navigation';
import LoginForm from './loginForm';
import { getUserFromSession } from '../session';

export default async function Login() {
    const user = await getUserFromSession();

    if (user !== null && user.passphraseHash !== undefined) {
        redirect('/vault');
    }

    return <LoginForm />;
}
