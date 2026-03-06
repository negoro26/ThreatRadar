import { MetadataRoute } from 'next';

export default function robots(): MetadataRoute.Robots {
    return {
        rules: {
            userAgent: '*',
            allow: '/',
            disallow: ['/api/'], // Suggested to hide internal API calls
        },
        sitemap: 'https://threat-radar-pearl.vercel.app/sitemap.xml',
    };
}
