<template>
<q-layout view="lHh Lpr lFf" style="background-color: rgb(239, 243, 246)">
    <q-header elevated height-hint="98">
        <q-toolbar class="text-primary bg-white">
            <q-toolbar-title>
                DuckSysEye内部测试版本v0.0.0.1
            </q-toolbar-title>
            <q-btn flat round dense icon="more_vert"></q-btn>
        </q-toolbar>
    </q-header>
    <q-drawer show-if-above :mini="miniState" @mouseover="miniState = false" @mouseout="miniState = true" :width="200" :breakpoint="500" bordered class="bg-white text-primary">
        <q-scroll-area class="fit">
            <q-list padding>
                <q-item :active="selectLabel == 'dashboard'" clickable v-ripple active-class="menu-active" @click="selectLabel = 'dashboard'" to="/page/dashboard">
                    <q-item-section avatar>
                        <q-icon name="dashboard" />
                    </q-item-section>
                    <q-item-section>
                        仪表盘
                    </q-item-section>
                </q-item>

                <q-item :active="selectLabel == 'report'" clickable v-ripple active-class="menu-active" @click="selectLabel = 'report'" to="/page/index">
                    <q-item-section avatar>
                        <q-icon name="report" />
                    </q-item-section>
                    <q-item-section>
                        警告列表
                    </q-item-section>
                </q-item>
            </q-list>
        </q-scroll-area>
    </q-drawer>

    <q-page-container>
        <router-view />
    </q-page-container>
</q-layout>
</template>

<script>
import {
  defineComponent
} from 'vue'

export default defineComponent({
  name: 'MainLayout',
  setup () {
    return {}
  },
  data: function () {
    return {
      selectLabel: 'dashboard',
      drawer: false,
      miniState: true
    }
  }
})
</script>

<style lang="sass">
.menu-active
  color: white
  background: #F2C037
</style>
