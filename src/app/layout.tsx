import type { Metadata } from 'next';
import Image from 'next/image';
import './globals.css';
import Link from 'next/link';
import { Header } from './header';

export const metadata: Metadata = {
    title: 'Passless',
    description: 'The Password-less Password Manager',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
    return (
        <html lang="en">
            <body>
                <Header />
                {children}
            </body>
        </html>
    );
}
