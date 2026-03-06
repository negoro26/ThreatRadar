import { MetadataRoute } from 'next';

export default function sitemap(): MetadataRoute.Sitemap {
    return [
        {
            url: 'https://threat-radar-pearl.vercel.app/', // Recommendation: Update with your actual domain
            lastModified: new Date(),
            changeFrequency: 'daily',
            priority: 1,
        },
        // Add additional routes here if you have more pages
    ];
}
