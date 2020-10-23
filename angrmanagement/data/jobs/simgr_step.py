import logging
from math import ceil

from .job import Job
from ...logic import GlobalInfo
from ...logic.threads import gui_thread_schedule, gui_thread_schedule_async

_l = logging.getLogger(__name__)


class SimgrStepJob(Job):
    def __init__(self, simgr, callback=None, until_branch=False, post_step_callback=None, pre_step_callback=None):
        super(SimgrStepJob, self).__init__('Simulation manager stepping')
        self._simgr = simgr
        self._callback = callback
        self._until_branch = until_branch
        self._post_step_callback = post_step_callback
        self._pre_step_callback = pre_step_callback
        self.step_progress = 0

    def run(self, inst):
        # TODO: hci: refactor: Make so the step progress is visible when "step till branch" is clicked
        # TODO: hci: refactor: Reuse some code from SimgrExploreJob
        if self._until_branch:
            orig_len = len(self._simgr.active)
            if orig_len > 0:
                while len(self._simgr.active) == orig_len:
                    self._simgr.step()
                    self._simgr.prune()
        else:
            self.step_progress = 0
            total_states = len(self._simgr.active)
            self._update_progress(f"Stepping {self.step_progress}/{total_states}")

            def blah(s):
                self.step_progress += 1
                self._update_progress(f"Stepping {self.step_progress}/{total_states}")
                s.inspect.remove_breakpoint("engine_process", filter_func=lambda bp: bp.action == blah)

            for s in self._simgr.active:
                s.inspect.b(event_type="engine_process", when="after", action=blah)

            self._simgr.step(step_func=self._post_step_callback, pre_func=self._pre_step_callback)
            self._simgr.prune()

        return self._simgr

    def _update_progress(self, text):
        def update_progress():
            GlobalInfo.main_window.status = text
        gui_thread_schedule(update_progress)

    def finish(self, inst, result):
        super(SimgrStepJob, self).finish(inst, result)
        if self._callback is not None:
            self._callback(result)

    def __repr__(self):
        if self._until_branch:
            return "Stepping %r until branch" % self._simgr
        else:
            return "Stepping %r" % self._simgr

    @classmethod
    def create(cls, simgr, **kwargs):
        def callback(result):
            simgr.am_event(src='job_done', job='step', result=result)

        return cls(simgr, callback=callback, **kwargs)
