<template>
  <div class="container">
    <div class="columns">
      <div class="column">
        <section class="hero">
          <div class="hero-body">
            <h1 class="title" v-if="OS.length">
              {{ OS[0].name }}
            </h1>
          </div>
        </section>
        <Filesystem :os="OS[0]" id="filesystem"/>
        <ProcessList :os="OS[0]" id="proclist"/>
        <SyscallTable :os="OS[0]" id="syscalltable"/>
      </div>
      <div class="column is-2">
        <nav class="panel">
          <p class="panel-heading">
          Menu
          </p>
          <div class="panel-block">
            <aside class="menu">
              <p class="menu-label">
              Online
              </p>
              <ul class="menu-list">
                <li>
                  <router-link to="#proclist">
                    Process List
                  </router-link>
                </li>
                <li>
                  <router-link to="#syscalltable">
                    Syscall Table
                  </router-link>
                </li>
              </ul>
            </aside>
          </div>
        </nav>
      </div>
    </div>
  </div>
</template>

<script>
import Filesystem from '@/components/Filesystem.vue'
import ProcessList from '@/components/ProcessList.vue'
import SyscallTable from '@/components/SyscallTable.vue'
import { OS_FOR_ID_QUERY } from '@/constants/graphql.js'

export default {
  data () {
    return {
      OS: [],
      Process: [],
      os_id: parseInt(this.$route.params.id),
      loading: 0
    }
  },
  components: {
    Filesystem,
    ProcessList,
    SyscallTable
  },
  apollo: {
    OS: {
      query: OS_FOR_ID_QUERY,
      variables () {
        return {
          id: this.os_id
        }
      }
    }
  }
}
</script>

<style>
#filesystem {
  height: 600px;
}
</style>
