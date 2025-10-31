import { NextResponse } from 'next/server';

export async function middleware(request) {
    const token = request.cookies.get("access_token")?.value;
    if (!token && (request.nextUrl.pathname === '/binovate')) {
        return NextResponse.redirect(new URL('/login', request.url))
    }
    if (token && (request.nextUrl.pathname === '/login' || request.nextUrl.pathname === '/register')) {
        return NextResponse.redirect(new URL('/binovate', request.url));
    }
    if (request.nextUrl.pathname === '/') {
        return NextResponse.redirect(new URL('/login', request.url));
    }
    return NextResponse.next();
    
}

export const config = {
    matcher: ['/', '/login', '/register', '/binovate/:path*']
};
