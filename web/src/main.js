import Vue from 'vue'
import App from './App'
import router from './router'

// Apollo
import { ApolloClient } from 'apollo-client'
import { HttpLink } from 'apollo-link-http'
import { setContext } from 'apollo-link-context'
import { InMemoryCache } from 'apollo-cache-inmemory'
import VueApollo from 'vue-apollo'

// Buefy
import Buefy from 'buefy'
import 'buefy/lib/buefy.css'

Vue.config.productionTip = false

const httpLink = new HttpLink({
  uri: 'http://localhost:7474/graphql/',
  credentials: 'same-origin'
  // uri: 'https://api.graph.cool/simple/v1/cj82xx3hx01es01203di1wz06'
})

const authLink = setContext((_, { headers }) => {
  // return the headers to the context so httpLink can read them
  return {
    headers: {
      ...headers,
      authorization: 'Basic bmVvNGo6YWRtaW4='
    }
  }
})

const apolloClient = new ApolloClient({
  link: authLink.concat(httpLink),
  cache: new InMemoryCache(),
  connectToDevTools: true
})

Vue.use(VueApollo)

const apolloProvider = new VueApollo({
  defaultClient: apolloClient,
  defaultOptions: {
    $loadingKey: 'loading'
  }
})

Vue.use(Buefy)

/* eslint-disable no-new */
new Vue({
  el: '#app',
  router,
  render: h => h(App),
  provide: apolloProvider.provide()
})
