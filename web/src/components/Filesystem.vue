<template>
  <section>
    <h1 class="title">Filesystem</h1>
    <tree :data="tree" node-text="name" class="tree" v-on:clicked="onClicked">
    </tree>
  </section>
</template>

<script>
import {tree} from 'vued3tree'
import { ROOT_INODE_QUERY, CHILD_INODES_QUERY } from '@/constants/graphql.js'

export default {
  data () {
    return {
      tree: null,
      loading: 0
    }
  },
  components: {
    tree
  },
  props: [
    'os'
  ],
  computed: {
    isLoading: function () {
      return Boolean(this.loading)
    }
  },
  methods: {
    onClicked: async function (event) {
      var result = await this.$apollo.query({
        query: CHILD_INODES_QUERY,
        variables: {
          parent: event.data.name
        }
      })
      var query = result['data']['Inode']
      for (var i = 0; i < query.length; i++) {
        if (query[i].hasChild != null) {
          var child = {
            id: query[i]['_id'],
            name: query[i]['name'],
            children: []
          }
          event.data.children.push(child)
        }
      }
    }
  },
  apollo: {
    root: {
      query: ROOT_INODE_QUERY,
      variables () {
        return {
          os_name: this.os.name
        }
      },
      update (data) {
        var root = data['OS'][0]['ownsFilesystem']
        this.tree = {
          id: root['_id'],
          name: root['name'],
          children: []
        }
      }
    },
    children: {
      query: {
        CHILD_INODES_QUERY,
        $skip: true
      }
    }
  }
}
</script>

<style>
.tree {
  width: 100%;
  height: 100%;
}

</style>
