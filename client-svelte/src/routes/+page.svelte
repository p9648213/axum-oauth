<script>
	import { onMount } from 'svelte';
	import { writable } from 'svelte/store';

	const user = writable('');
	const error = writable('');

	onMount(async () => {
		try {
			const res = await fetch('http://localhost:5000/api/auth/me', { credentials: 'include' });
			if (!res.ok) throw new Error(await res.text());
			const data = await res.json();
			user.set(data);
		} catch (err) {
			if (err instanceof Error) {
				error.set(err.message);
			}
		}
	});
</script>

<div style="height: 100vh; display: flex; justify-content: center; align-items: center;">
	<div>
		<h1>Google Oauth</h1>
		<a class="login-button dark" href="http://localhost:5000/api/auth/google/login">
			<img alt="Google Logo" src="/google-logo.png" />
			<span>Login with Google</span>
		</a>
		{#if $error}
			<p style="color: red;">{$error}</p>
		{/if}
		{#if $user}
			<pre>{JSON.stringify($user, null, 2)}</pre>
		{/if}
	</div>
</div>

<style lang="scss">
	.login-button {
		width: 100%;
		padding: 0.5rem;
		border-radius: 0.5rem;
		border: 1px solid rgba(0, 0, 0, 0.2);
		display: flex;
		flex-direction: row;
		align-items: center;
		gap: 1rem;
		text-decoration: none;

		&:hover {
			background-color: rgba(0, 0, 0, 0.1);
		}

		&.dark:hover {
			background-color: rgba(0, 0, 0, 0.2);
		}

		img {
			width: 32px;
			height: 32px;
		}

		span {
			display: inline-block;
		}
	}
</style>
