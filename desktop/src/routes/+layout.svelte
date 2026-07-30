<script lang="ts">
  import "../styles/app.css";
  import type { Snippet } from "svelte";

  let { children }: { children: Snippet } = $props();
</script>

<div id="app-root">
  {@render children()}
</div>
