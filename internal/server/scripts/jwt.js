export function decode(rawToken) {
    const base64 = rawToken.split('.')?.[1]?.replace('-', '+')?.replace('_', '/');
    return JSON.parse(atob(base64));
}
