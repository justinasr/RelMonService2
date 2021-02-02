<template>
  <v-app>
    <v-app-bar app style="background-color: white;">
      <a href="" style="text-decoration: none; color: rgba(0, 0, 0, 0.87);">
        <v-toolbar-title class="headline">
          <span>RelMon</span>
          <span class="font-weight-light">Service</span>
        </v-toolbar-title>
      </a>
      <v-spacer></v-spacer>
      <div style="text-align: right; line-height: 28px;">
        <small class="font-weight-light">Logged in as</small> {{userInfo.name}}
        <img style="width: 16px; height: 16px;" v-if="userInfo.authorized" src="static/star.png"/>
      </div>
    </v-app-bar>

    <v-main>
      <MainComponent :userInfo="userInfo" />
    </v-main>
  </v-app>
</template>

<script>

import MainComponent from './components/MainComponent';
import axios from 'axios'

export default {
  name: 'App',
  components: {
    MainComponent,
  },
  data: () => ({
    userInfo: {'name': '', 'authorized': false},
  }),
  created() {
    this.fetchUserInfo();
  },
  methods: {
    fetchUserInfo() {
      let component = this;
      axios.get('api/user').then(response => {
        component.userInfo.name = response.data.fullname;
        component.userInfo.authorized = response.data.authorized_user;
      });
    },
  }
};
</script>

<style>

.bigger-text {
  font-size: 1.5rem;
  word-break: break-all;
}

</style>