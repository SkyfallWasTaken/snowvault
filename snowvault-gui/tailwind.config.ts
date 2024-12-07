import forms from '@tailwindcss/forms';
import typography from '@tailwindcss/typography';
import { skeleton, contentPath } from '@skeletonlabs/skeleton/plugin';
import * as themes from '@skeletonlabs/skeleton/themes';

import type { Config } from 'tailwindcss';

export default {
	content: ['./src/**/*.{html,js,svelte,ts}', contentPath(import.meta.url, 'svelte')],
	theme: {
		extend: {}
	},
	plugins: [
		skeleton({
			// NOTE: each theme included will be added to your CSS bundle
			themes: [themes.cerberus, themes.rose]
		}),
		forms,
		typography
	]
} satisfies Config;
