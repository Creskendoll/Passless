'use server';

import { redirect } from 'next/navigation';
import RegisterForm from './registerForm';
import { getUserFromSession } from '../session';

// TODO: user session will be created after user simply visits this page!
export default async function Register() {
    const user = await getUserFromSession();

    if (user !== null && user.passphraseHash !== undefined) {
        redirect('/vault');
    }

    return <RegisterForm />;
}
