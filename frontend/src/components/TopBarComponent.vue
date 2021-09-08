<template>
  <div>
    <div class="elevation-3 mb-2 pl-4 pr-4 pt-2 pb-2" v-if="userInfo.authorized" style="background: white">
      <v-row style="text-align: center">
        <v-col cols=12>
          <v-btn small color="primary" v-if="!expandedPanels.length" class="mr-1 ml-1" @click="expandedPanels = expandedPanels.length ? [] : [0]" title="Create a new RelMon">
            Create New RelMon
          </v-btn>
          <v-btn small color="primary" v-if="!expandedPanels.length" class="mr-1 ml-1" @click="forceRefresh()" title="Trigger RelMon Service to check RelMon progress in HTCondor. This happens automatically every 10 minutes">
            Trigger Status Refresh
          </v-btn>
        </v-col>
      </v-row>
      <v-expansion-panels multiple v-model="expandedPanels">
        <v-expansion-panel :key="0" class="elevation-0">
          <v-expansion-panel-content class="expansion-panel-content">
            <v-row>
              <v-col v-if="!isEditing" cols=12>
                <span class="bigger-text font-weight-light">Creating</span> <span class="bigger-text ml-2">a new RelMon</span>
              </v-col>
              <v-col v-if="isEditing" cols=12>
                <span class="bigger-text font-weight-light">Editing</span> <span class="bigger-text ml-2">{{relmonWrapper.relmon.name}}</span>
              </v-col>
              <v-col cols=12 sm=12 md=8 lg=8>
                <span class="font-weight-light">Name:</span><input type="text" class="thin-border" v-model="relmonWrapper.relmon.name">
              </v-col>
              <v-col v-if="isEditing" cols=12 sm=12 md=4 lg=4>
                <span class="font-weight-light">ID:</span><input type="text" class="thin-border" :disabled="true" v-model="relmonWrapper.relmon.id">
              </v-col>
            </v-row>
            <v-row>
              <v-col cols=12>
                <v-tabs :grow="true" :centered="true">
                  <v-tabs-slider></v-tabs-slider>
                  <v-tab v-for="category in relmonWrapper.relmon.categories" :key="category.name" :href="`#tab-${category.name}`">
                    <div>
                      <div>
                        {{ category.name }}
                      </div>
                      <small class="font-weight-light">
                        {{listLength(category.reference)}} vs. {{listLength(category.target)}}
                      </small>
                    </div>
                  </v-tab>
                  <v-tab-item v-for="category in relmonWrapper.relmon.categories" :key="category.name" :value="'tab-' + category.name">
                    <v-row>
                      <v-col cols=12>
                        {{category.name}} <span class="font-weight-light">references:</span><br>
                        <textarea class="thin-border" v-model="category.reference"></textarea>
                        {{category.name}} <span class="font-weight-light">targets:</span><br>
                        <textarea class="thin-border" v-model="category.target"></textarea>
                      </v-col>
                      <v-col cols=12
                             sm=12
                             :md="(isEditing && relmonWrapper.relmon.status == 'done' ? 4 : 6)"
                             :lg="(isEditing && relmonWrapper.relmon.status == 'done' ? 4 : 6)">
                        <span class="font-weight-light mr-2">Pairing:</span>
                        <v-btn-toggle mandatory v-model="category.automatic_pairing" class="radio-buttons">
                          <v-btn small :value="true">
                            Automatic
                          </v-btn>
                          <v-btn small :value="false">
                            Manual
                          </v-btn>
                        </v-btn-toggle>
                      </v-col>
                      <v-col cols=12
                             sm=12
                             :md="(isEditing && relmonWrapper.relmon.status == 'done' ? 4 : 6)"
                             :lg="(isEditing && relmonWrapper.relmon.status == 'done' ? 4 : 6)">
                        <span class="font-weight-light mr-2">HLT:</span>
                        <v-btn-toggle mandatory v-model="category.hlt" class="radio-buttons">
                          <v-btn small :value="'no'">
                            No HLT
                          </v-btn>
                          <v-btn small :value="'only'" :disabled="category.name === 'Generator'">
                            Only HLT
                          </v-btn>
                          <v-btn small :value="'both'" :disabled="category.name === 'Generator'">
                            Both
                          </v-btn>
                        </v-btn-toggle>
                      </v-col>
                      <v-col v-if="isEditing && relmonWrapper.relmon.status == 'done'" cols=12 sm=12 md=4 lg=4>
                        <span class="font-weight-light mr-2">Force re-run:</span>
                        <v-btn-toggle mandatory v-model="category.rerun" class="radio-buttons">
                          <v-btn small :value="false">
                            No
                          </v-btn>
                          <v-btn small :value="true">
                            Yes
                          </v-btn>
                        </v-btn-toggle>
                      </v-col>
                    </v-row>
                  </v-tab-item>
                </v-tabs>
              </v-col>
            </v-row>
            <v-row>
              <v-col>
                <v-btn v-if="!isEditing" small class="ma-1" color="primary" :disabled="!relmonWrapper.relmon.name" @click="updateRelmon('create')">Create</v-btn>
                <v-btn v-if="isEditing" small class="ma-1" color="primary" :disabled="!relmonWrapper.relmon.name" @click="editOverlay = true">Save</v-btn>
                <v-btn small class="ma-1" color="error" @click="cleanup()">Cancel</v-btn>
              </v-col>
            </v-row>
          </v-expansion-panel-content>
        </v-expansion-panel>
      </v-expansion-panels>
    </div>
    <div class="elevation-3 mb-2 pl-4 pr-4 pt-2 pb-2" v-if="!expandedPanels.length" style="background: white">
      <v-row>
        <v-spacer></v-spacer>
        <v-col cols=12 sm=12 md=6 lg=6>
          <div class="v-btn--contained search-wrapper">
            <div class="thin-border search-input-wrapper">
              <input v-model="query" v-on:keyup.enter="search" placeholder="Search by RelMon name, status or ID" />
            </div>
            <v-btn small color="primary" class="ma-0" @click="search()" title="Perform search in RelMon Service">
              Search
            </v-btn>
          </div>
        </v-col>
        <v-spacer></v-spacer>
      </v-row>
    </div>

    <v-overlay :absolute="false"
               :opacity="0.95"
               :z-index="3"
               :value="editOverlay"
               style="text-align: center">
      <span v-if="relmonWrapper.relmon.status == 'done'">This will update {{relmonWrapper.relmon.name}}. If you have changed any categories, they will be redone from scratch.</span>
      <span v-if="relmonWrapper.relmon.status != 'done'">This will update and reset {{relmonWrapper.relmon.name}}. All progress will be lost and RelMon will be redone from scratch.</span>
      <br>Are you sure you want to update {{relmonWrapper.relmon.name}}?<br>
      <v-btn color="error"
             class="ma-1"
             small
             v-if="!isRefreshing"
             @click="updateRelmon('edit')">
        Yes
      </v-btn>
      <v-btn color="primary"
             class="ma-1"
             small
             v-if="!isRefreshing"
             @click="editOverlay = false">
        No
      </v-btn>
      <v-progress-circular indeterminate
                           v-if="isRefreshing"
                           color="primary"></v-progress-circular>
    </v-overlay>

    <v-overlay :absolute="false"
               :opacity="0.95"
               :z-index="3"
               :value="creatingOverlay"
               style="text-align: center">
      Creating {{relmonWrapper.relmon.name}}<br>
      <v-progress-circular indeterminate
                     color="primary"></v-progress-circular>
    </v-overlay>

    <v-overlay :absolute="false"
               :opacity="0.95"
               :z-index="3"
               :value="forceRefreshOverlay"
               style="text-align: center">
      Refresh has been triggered. RelMon Service will now check how submitted RelMons are progressing in HTCondor. This may take a few minutes. This refresh happens automatically on it's own every 10 minutes.<br>
      <v-btn color="primary"
             class="ma-1"
             small
             @click="forceRefreshOverlay = false; refetchRelmons();">
        Close
      </v-btn>
    </v-overlay>
  </div>
</template>

<script>
import axios from 'axios'
export default {
  name: 'TopBarComponent',
  data () {
    return {
      categories: ['Data', 'FullSim', 'FastSim', 'Generator', 'FullSim PU', 'FastSim PU'],
      expandedPanels: [],
      relmonWrapper: {'relmon': {}},
      isEditing: false,
      editOverlay: false,
      creatingOverlay: false,
      isRefreshing: false,
      forceRefreshOverlay: false,
      query: ''
    }
  },
  created () {
    this.cleanup();
  },
  watch: {

  },
  props: {
    userInfo: {},
  },
  components: {
  },
  methods: {
    updateRelmon(action) {
      var relmonClone = JSON.parse(JSON.stringify(this.relmonWrapper.relmon))
      let component = this;
      this.isRefreshing = true;
      if (action === 'create') {
        this.creatingOverlay = true;
      }
      relmonClone.categories.forEach(function(item, index) {
        item['name'] = item['name'].replace(' ', '_')
        item['reference'] = item['reference'].split('\n').map(x => x.replace(/\s/g, "")).filter(Boolean)
        item['target'] = item['target'].split('\n').map(x => x.replace(/\s/g, "")).filter(Boolean)
      })
      axios.post('api/' + action, relmonClone).then(response => {
        setTimeout(function(){
          component.refetchRelmons();
          component.cleanup();
          component.isRefreshing = false;
        }, action === 'create' ? 5000 : 500);
      }).catch(error => {
        component.isRefreshing = false;
        component.editOverlay = false;
        component.creatingOverlay = false;
        alert(error.response.data.message);
      });
    },
    cleanup() {
      this.isEditing = false
      this.editOverlay = false;
      this.creatingOverlay = false;
      this.relmonWrapper['relmon'] = this.createEmptyRelmon();
      this.expandedPanels = [];
    },
    startEditing(relmon) {
      if (relmon) {
        var relmonClone = JSON.parse(JSON.stringify(relmon))
        relmonClone.categories.forEach(function(item, index) {
          item['name'] = item['name'].replace('_', ' ')
          item['reference'] = item['reference'].map(x => x['name'].replace(/\s/g, "")).filter(Boolean).join('\n')
          item['target'] = item['target'].map(x => x['name'].replace(/\s/g, "")).filter(Boolean).join('\n')
          item['rerun'] = false
        })
        this.isEditing = true;
        relmonClone['categories'] = this.addMissingCategories(relmonClone.categories);
        this.expandedPanels = [0];
        window.scrollTo(0,0);
        this.relmonWrapper.relmon = relmonClone;
      } else {
        this.cleanup()
      }
    },
    listLength(l) {
      return l.split('\n').map(x => x.replace(/\s/g, "")).filter(Boolean).length;
    },
    createEmptyRelmon() {
      return {'name': '',
              'categories': this.addMissingCategories([])}
    },
    addMissingCategories(categories) {
      let existingCategoryNames = categories.map(x => x['name'])
      this.categories.forEach(function(item, index) {
        if (!existingCategoryNames.includes(item)) {
          categories.push({'name': item,
                           'hlt': item === 'Generator' ? 'no' : 'both',
                           'automatic_pairing': true,
                           'reference':'',
                           'target': '',
                           'rerun': false})
        }
      })
      let component = this
      categories = categories.sort(function(a, b) {return component.categories.indexOf(a['name']) - component.categories.indexOf(b['name'])})
      return categories
    },
    forceRefresh() {
      let component = this;
      axios.get('api/tick').then(response => {
        component.forceRefreshOverlay = true;
      });
    },
    refetchRelmons() {
      this.$emit('refetchRelmons')
    },
    search() {
      let urlParams = Object.fromEntries(new URLSearchParams(window.location.search));
      urlParams['q'] = this.query;
      if (this.query.length == 0) {
        delete urlParams['q'];
      }
      urlParams['page'] = 0;
      urlParams = new URLSearchParams(urlParams);
      window.history.replaceState('search', '', '?' + urlParams.toString());

      this.refetchRelmons();
      this.query = '';
    }
  }
}
</script>

<style>

textarea{
  width: 100%;
  min-height: 250px;
  padding-left: 6px;
}

input {
  padding-left: 6px;
  width: 100%;
}

.thin-border {
  border-style: solid;
  border-width: 0.5px;
  border-color: rgb(169, 169, 169);
  border-radius: 4px;
}

.v-tab {
  color: rgb(0, 0, 0, 0.87) !important;
}

.v-tab--active {
  color: white !important;
  background-color: var(--v-primary-base);
}

.v-tabs-slider {
  display: none !important;
}

.radio-buttons > .v-item--active {
  color: white !important;
  background-color: var(--v-primary-base) !important;
}

.elevation-0::before {
  box-shadow: none !important;
  -webkit-box-shadow: none !important;
}

.radio-buttons .v-btn::before {
  opacity: 0 !important;
  -webkit-transition: none !important;
  transition: none !important;
}

.search-wrapper {
  display: flex;
  border-radius: 4px;
}

.search-input-wrapper {
  flex-grow: 1;
  border-radius: 4px 0px 0px 4px;
}

.search-input-wrapper > input {
  height: 100%;
  border: none;
}

.search-wrapper button {
  border-radius: 0px 4px 4px 0px;
  box-shadow: none;
  -webkit-box-shadow: none;
}

.expansion-panel-content > div {
  padding: 0 !important;
}

</style>
