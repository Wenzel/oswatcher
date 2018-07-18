<template>
<li>
  {{ inode.name }}
</li>
</template>
<script>
export default {
  props: {
    inode: {
      type: Object,
      required: true
    }
  }
}

</script>

<style>
</style>
