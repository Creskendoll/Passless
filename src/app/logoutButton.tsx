'use client';

export async function LogoutButton() {
    return (
        <button
            className="block button bg-dark-purple m-3 mx-6 px-6 py-2 w-fit h-fit rounded-3xl text-white font-bold text-center"
            onClick={async () => {
                await fetch('/api/user/logout', {
                    method: 'POST',
                });
                window.location.reload();
            }}
        >
            Log out
        </button>
    );
}
