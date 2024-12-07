<script lang="ts">
	import { invoke } from '@tauri-apps/api/core';

	let name = $state('');
	let greetMsg = $state('');

	async function greet(event: Event) {
		event.preventDefault();
		// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
		greetMsg = await invoke('load_from_', { name });
	}
</script>

<h1>Hi!</h1>
